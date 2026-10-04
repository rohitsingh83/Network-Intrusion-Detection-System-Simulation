"""Convenience launcher; local by default, platform PORT-aware for deployment."""

import os

import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "backend.app:app",
        host=os.getenv("IDS_HOST", "127.0.0.1"),
        port=int(os.getenv("IDS_PORT", os.getenv("PORT", "8000"))),
        reload=os.getenv("IDS_RELOAD", "false").lower() in {"1", "true", "yes"},
    )
