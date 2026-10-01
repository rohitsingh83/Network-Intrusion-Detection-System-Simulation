"""
API Entry Point Alias
=====================
Exports FastAPI application instance for test clients and modular runners.
"""

from backend.app import app

__all__ = ["app"]
