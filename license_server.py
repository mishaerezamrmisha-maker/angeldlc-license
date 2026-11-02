# AngelDLC License Server — выдача ключей, привязка к железу (HWID), выдача и проверка
# короткоживущих токенов сессии. Без внешних сервисов, SQLite + Flask.
#
# Установка:  pip install flask
# Запуск:     ADMIN_TOKEN=секрет SIGNING_KEY=другой_секрет python license_server.py
# Прод:       запускать за nginx/Caddy с https, через gunicorn/waitress, не через flask run.
#
# Логика:
#   1. Ты (админ) создаёшь ключи через /admin/keys/create — ключ привязан к сроку действия.
#   2. Клиент при старте шлёт /license/activate {key, hwid}.
#      - Если ключ свободен — привязывается к этому hwid навсегда (до ревока).
#      - Если занят другим hwid — отказ. Так один ключ = одна машина.
#      - Если совпадает — выдаётся session-токен на SESSION_TTL секунд.
#   3. Лаунчер держит токен в памяти и присылает его в /license/verify перед тем, как
#      разрешить скачать/запустить чит. Токен подписан HMAC и быстро протухает, поэтому
#      шарить голый токен почти бесполезно — он быстро умрёт, а re-activate спросит ключ.
#   4. /admin/keys/revoke мгновенно убивает ключ: новые verify с его токенами будут отказывать
#      после истечения текущего короткого TTL (максимум SESSION_TTL секунд простоя бана).

import os, sqlite3, time, hmac, hashlib, base64, json, secrets, re
from flask import Flask, request, jsonify, g

DB_PATH = os.environ.get("LICENSE_DB", "licenses.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")
SIGNING_KEY = os.environ.get("SIGNING_KEY")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "900"))       # 15 минут — живость токена
KEY_RE = re.compile(r"^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$")        # формат: XXXX-XXXX-XXXX-XXXX
HWID_RE = re.compile(r"^[a-f0-9]{16,128}$")

if not ADMIN_TOKEN or not SIGNING_KEY:
    raise SystemExit("Задайте переменные окружения ADMIN_TOKEN и SIGNING_KEY перед запуском (это секреты, не публикуй их).")

app = Flask(__name__)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d is not None:
        d.close()

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        hwid TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked INTEGER NOT NULL DEFAULT 0,
        note TEXT
    )""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_keys_hwid ON keys(hwid)")
    con.commit(); con.close()

def new_key():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # без похожих символов (0/O, 1/I)
    group = lambda: "".join(secrets.choice(alphabet) for _ in range(4))
    return "-".join(group() for _ in range(4))

def sign(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(SIGNING_KEY.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode() + "." + base64.urlsafe_b64encode(sig).decode()

def verify_token(token: str):
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = base64.urlsafe_b64decode(raw_b64.encode())
        sig = base64.urlsafe_b64decode(sig_b64.encode())
        expected = hmac.new(SIGNING_KEY.encode(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(raw)
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def require_admin():
    tok = request.headers.get("X-Admin-Token", "")
    return hmac.compare_digest(tok, ADMIN_TOKEN)

def key_row(k):
    return db().execute("SELECT * FROM keys WHERE key=?", (k,)).fetchone()

# ---------- админ: управление ключами ----------
@app.post("/admin/keys/create")
def admin_create():
    if not require_admin():
        return jsonify(error="forbidden"), 403
    body = request.get_json(silent=True) or {}
    days = int(body.get("days", 0))  # 0 = бессрочный
    note = str(body.get("note", ""))[:200]
    k = new_key()
    now = int(time.time())
    exp = now + days * 86400 if days > 0 else None
    db().execute("INSERT INTO keys (key, hwid, created_at, expires_at, note) VALUES (?,NULL,?,?,?)",
                 (k, now, exp, note))
    db().commit()
    return jsonify(key=k, expires_at=exp)

@app.post("/admin/keys/revoke")
def admin_revoke():
    if not require_admin():
        return jsonify(error="forbidden"), 403
    k = (request.get_json(silent=True) or {}).get("key", "")
    db().execute("UPDATE keys SET revoked=1 WHERE key=?", (k,))
    db().commit()
    return jsonify(ok=True)

@app.post("/admin/keys/reset_hwid")
def admin_reset_hwid():
    # если человек сменил компьютер/переустановил систему — отвязать ключ от старого HWID
    if not require_admin():
        return jsonify(error="forbidden"), 403
    k = (request.get_json(silent=True) or {}).get("key", "")
    db().execute("UPDATE keys SET hwid=NULL WHERE key=?", (k,))
    db().commit()
    return jsonify(ok=True)

@app.get("/admin/keys/list")
def admin_list():
    if not require_admin():
        return jsonify(error="forbidden"), 403
    rows = db().execute("SELECT key, hwid, created_at, expires_at, revoked, note FROM keys ORDER BY created_at DESC").fetchall()
    return jsonify(keys=[dict(r) for r in rows])

# ---------- клиент: активация и проверка ----------
@app.post("/license/activate")
def activate():
    body = request.get_json(silent=True) or {}
    k, hwid = str(body.get("key", "")).strip().upper(), str(body.get("hwid", "")).strip().lower()
    if not KEY_RE.match(k):
        return jsonify(error="bad_key_format"), 400
    if not HWID_RE.match(hwid):
        return jsonify(error="bad_hwid_format"), 400

    row = key_row(k)
    if row is None:
        return jsonify(error="key_not_found"), 404
    if row["revoked"]:
        return jsonify(error="key_revoked"), 403
    if row["expires_at"] and row["expires_at"] < time.time():
        return jsonify(error="key_expired"), 403

    if row["hwid"] is None:
        db().execute("UPDATE keys SET hwid=? WHERE key=?", (hwid, k))
        db().commit()
    elif row["hwid"] != hwid:
        return jsonify(error="key_bound_to_another_device"), 403

    exp = int(time.time()) + SESSION_TTL
    token = sign({"key": k, "hwid": hwid, "exp": exp})
    return jsonify(token=token, expires_at=exp)

@app.post("/license/verify")
def verify():
    body = request.get_json(silent=True) or {}
    token = str(body.get("token", ""))
    payload = verify_token(token)
    if payload is None:
        return jsonify(valid=False, error="invalid_or_expired"), 401

    row = key_row(payload["key"])
    if row is None or row["revoked"] or (row["expires_at"] and row["expires_at"] < time.time()):
        return jsonify(valid=False, error="key_no_longer_valid"), 403
    if row["hwid"] != payload["hwid"]:
        return jsonify(valid=False, error="hwid_mismatch"), 403

    return jsonify(valid=True, expires_at=payload["exp"])

@app.get("/healthz")
def health():
    return jsonify(ok=True)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8787")))
