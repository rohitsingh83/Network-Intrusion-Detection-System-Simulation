# Backend utilities

Shared UTC timestamp normalization lives in `ids/timeutils.py`; database connection and row conversion helpers live in `backend/database.py`. Keep future transport-specific helpers here rather than duplicating validation in route handlers.
