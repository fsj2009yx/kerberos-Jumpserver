# Verify Server WebUI

Vue 3 + JavaScript WebUI for the V server WEB API.

## Commands

```bash
npm install
npm run dev
```

The dev server listens on `http://localhost:5185` and proxies `/api` to `http://127.0.0.1:9885`.

Implemented Go handlers:

- `GET /api/status`
- `GET /api/sessions`

Documented but not registered in the current Go code:

- `GET /api/auth_log?limit=100`
- `GET /api/pty_log?limit=100`
- `GET /api/cert/:id`
- `POST /api/verify_cert`
