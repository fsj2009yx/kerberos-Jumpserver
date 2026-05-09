# TGS Server WebUI

Vue 3 + JavaScript WebUI for the TGS server WEB API.

## Commands

```bash
npm install
npm run dev
```

The dev server listens on `http://localhost:5182` and proxies `/api` to `http://127.0.0.1:9882`.

Implemented Go handlers:

- `GET /api/status`
- `GET /api/services`

Documented but not registered in the current Go code:

- `GET /api/tgs_log?limit=100`
