# AS Server WebUI

Vue 3 + JavaScript WebUI for the AS server WEB API.

## Commands

```bash
npm install
npm run dev
```

The dev server listens on `http://localhost:5181` and proxies `/api` to `http://127.0.0.1:9881`.

Implemented Go handlers:

- `GET /api/status`
- `GET /api/clients`
- `GET /api/cert/:id`
- `GET /api/keys_summary`

Documented but not registered in the current Go code:

- `GET /api/auth_log?limit=100&offset=0`
