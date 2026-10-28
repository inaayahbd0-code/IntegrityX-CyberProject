# 🛡️ IntegrityX: File Integrity Checker

IntegrityX detects unauthorized changes to files. It records a SHA-256 hash of every file in a folder, stores the baselines in SQLite, and flags files that are **MODIFIED**, **DELETED** or **NEW** on later scans. A Streamlit dashboard shows the results in real time.

**Live demo:** https://integrityx-inaaya.streamlit.app/

## Features
- Recursive scanning of files and nested folders
- SHA-256 hashing in chunks, so large files don't fill memory
- SQLite baseline store with status tracking (`NEW`, `MATCH`, `MODIFIED`, `DELETED`)
- Streamlit dashboard: metrics, alert banner, searchable and filterable logs, auto-refresh every 10 s
- Built-in demo: create a baseline, tamper with a file, re-scan and watch the alert appear
- Desktop notifications when run locally (optional, via `plyer`)

## How it works
1. `scanner.py` walks the target and hashes each file with `hashlib.sha256`.
2. Hashes are compared with the baseline stored in `hashdatabase.db`.
3. Each file gets a status and the database is updated.
4. `app.py` reads the database and renders the dashboard.

## Run locally
```bash
git clone https://github.com/inaayahbd0-code/IntegrityX.git
cd IntegrityX
pip install -r requirements.txt
streamlit run app.py
```

Or use the scanner from the command line:
```bash
python scanner.py /path/to/folder
```
Run it again later to see which files changed.

## Tech stack
Python, SQLite3, Streamlit, hashlib (SHA-256), pandas

## Project structure
```
scanner.py        # hashing, comparison and SQLite storage
app.py            # Streamlit dashboard
requirements.txt
```
