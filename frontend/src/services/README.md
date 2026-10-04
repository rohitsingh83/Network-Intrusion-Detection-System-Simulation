# Frontend service layer

`api.js` wraps same-origin fetch calls, attaches the optional local write API key, handles JSON errors, and exports escaping/date/number formatters. The browser never calls a separate localhost service; Vite proxies `/api` during development and FastAPI serves the integrated app on one origin.
