# Frontend notes

SentinelFlow's console is a dependency-light JavaScript SPA so the dashboard can run offline and is served by FastAPI without external fonts, CDNs, chart packages, or remote assets. `package.json` includes Vite for an optional developer workflow; the API-hosted UI works without Node.js.

- Local integrated UI: open `http://127.0.0.1:8000/` after starting FastAPI.
- Optional Vite development server: `npm install`, then `npm run dev` (API requests are proxied to port 8000).
- Charts use inline SVG and all alert / note content is escaped before insertion into the DOM.
