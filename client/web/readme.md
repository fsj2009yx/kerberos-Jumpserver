# Web

Electron + TypeScript skeleton for the client UI.

## Features

- Electron main process (`main.ts`)
- Secure preload bridge (`preload.ts`)
- Embedded API skeleton with Express (`api/server.ts`)
- API route example (`api/routes/system.ts`)
- 2-column renderer layout:
	- Left: menu panel
	- Right: main content panel

## Structure

```text
web/
	main.ts
	preload.ts
	package.json
	tsconfig.json
	api/
		server.ts
		routes/
			system.ts
	renderer/
		index.html
		styles.css
		app.ts
		types.d.ts
```

## Run

```bash
cd client/audit
npm install
npm start
```

Default local API endpoint used by renderer bridge:

- `GET http://127.0.0.1:3001/api/system/health`