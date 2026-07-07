# ReferenceBridge

ReferenceBridge is a Flask employment reference app backed by SQLite.

## Setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py init_db.py
```

## Run locally

```powershell
$env:SECRET_KEY = "replace-with-a-long-random-value"
$env:ADMIN_PASSWORD = "replace-this-password"
py app.py
```

Open `http://127.0.0.1:5000`.

## Configuration

- `SECRET_KEY`: Flask session signing key. Required for production.
- `ADMIN_PASSWORD`: password for `/dashboard` and `/database-view`. Defaults to `changeme` for local development only.
- `DATABASE_PATH`: optional absolute path to the SQLite database. Defaults to `references.db` beside `app.py`.
- `FLASK_DEBUG`: set to `1` only for local debugging.

## Tests

```powershell
py -m pytest
```

