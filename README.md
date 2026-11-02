# AngelDLC License Server

## Запуск локально
```
pip install -r requirements.txt
set ADMIN_TOKEN=длинная_случайная_строка        (Windows: set, Linux/Mac: export)
set SIGNING_KEY=другая_длинная_случайная_строка
python license_server.py
```

## Продакшен
- Запускай за https (Caddy/nginx/Cloudflare Tunnel), не выставляй Flask dev-сервер напрямую в интернет.
- `ADMIN_TOKEN` и `SIGNING_KEY` — секреты. Никогда не коммить их в репозиторий, не класть в клиент/лаунчер.
- Рекомендуемый хостинг: любая VPS за 2-3$/мес (Timeweb, Hetzner и т.п.) + Caddy для автоматического https,
  либо Render/Railway с прописанными переменными окружения.
- Файл `licenses.db` — это SQLite, делай его бэкап регулярно (это твоя база всех ключей).

## Создать ключ
```
curl -X POST https://ТВОЙ_ДОМЕН/admin/keys/create \
  -H "X-Admin-Token: ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"days\": 30, \"note\": \"продажа #1\"}"
```
`days: 0` — бессрочный ключ.

## Отозвать ключ (бан)
```
curl -X POST https://ТВОЙ_ДОМЕН/admin/keys/revoke \
  -H "X-Admin-Token: ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"key\": \"XXXX-XXXX-XXXX-XXXX\"}"
```

## Если человек сменил ПК / переустановил Windows
```
curl -X POST https://ТВОЙ_ДОМЕН/admin/keys/reset_hwid \
  -H "X-Admin-Token: ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"key\": \"XXXX-XXXX-XXXX-XXXX\"}"
```
