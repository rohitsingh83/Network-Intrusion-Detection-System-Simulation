# Persistence model notes

SQLite table definitions, constraints, foreign keys, and indexes are centralized in `backend/database.py` so schema initialization remains easy to follow. The table contract is documented in `docs/DATA_DICTIONARY.md`. This folder is reserved for future typed persistence models/migrations if the project grows beyond the current small SQLite service.
