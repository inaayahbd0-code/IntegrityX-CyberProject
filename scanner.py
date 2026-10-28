"""IntegrityX scanner: SHA-256 baselines stored in SQLite.
"""
import hashlib
import os
import sqlite3
import sys

DB_PATH = os.environ.get("INTEGRITYX_DB", "hashdatabase.db")
CHUNK_SIZE = 64 * 1024

NEW, MATCH, MODIFIED, DELETED = "NEW", "MATCH", "MODIFIED", "DELETED"


def get_connection(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS baselines(
               file_path   TEXT PRIMARY KEY,
               hash_data   TEXT,
               last_modify REAL,
               status      TEXT DEFAULT 'MATCH'
           )"""
    )
    return conn


def generate_hash(path):
    """Return the SHA-256 hex digest of a file, or None if unreadable."""
    try:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                sha.update(chunk)
        return sha.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def read_target(target):
    """Hash a single file or every file under a folder (recursive)."""
    target = os.path.realpath(target)
    scanned = {}
    if os.path.isfile(target):
        h = generate_hash(target)
        if h:
            scanned[target] = h
    elif os.path.isdir(target):
        for root, _dirs, files in os.walk(target):
            for name in files:
                full = os.path.join(root, name)
                h = generate_hash(full)
                if h:
                    scanned[full] = h
    return scanned


def load_baselines(conn, target):
    """Previously stored hashes for everything under target."""
    target = os.path.realpath(target)
    prefix = target.rstrip(os.sep) + os.sep
    rows = conn.execute(
        "SELECT file_path, hash_data, status FROM baselines "
        "WHERE file_path = ? OR substr(file_path, 1, ?) = ?",
        (target, len(prefix), prefix),
    ).fetchall()
    return {p: {"hash": h, "status": s} for p, h, s in rows}


def compare(current, old):
    """Return {path: status} by comparing current hashes to the baseline."""
    statuses = {}
    for path in set(current) | set(old):
        if path not in current:
            statuses[path] = DELETED
        elif path not in old:
            statuses[path] = NEW
        elif current[path] != old[path]["hash"]:
            statuses[path] = MODIFIED
        else:
            statuses[path] = MATCH
    return statuses


def save(conn, current, old, statuses):
    for path, status in statuses.items():
        if status == DELETED:
            conn.execute(
                "UPDATE baselines SET status = ? WHERE file_path = ?",
                (DELETED, path),
            )
        else:
            mtime = os.path.getmtime(path) if os.path.exists(path) else 0.0
            conn.execute(
                "INSERT OR REPLACE INTO baselines "
                "(file_path, hash_data, last_modify, status) VALUES (?,?,?,?)",
                (path, current[path], mtime, status),
            )
    conn.commit()


def scan(target, db_path=None):
    """Scan target, update the database, return {path: status}."""
    conn = get_connection(db_path)
    try:
        old = load_baselines(conn, target)
        current = read_target(target)
        statuses = compare(current, old)
        save(conn, current, old, statuses)
        return statuses
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter directory/file to be checked: ")
    results = scan(target)
    if not results:
        print("Nothing found to scan.")
    for path, status in sorted(results.items()):
        print(f"[{status:8}] {path}")
    counts = {s: list(results.values()).count(s) for s in set(results.values())}
    print("Summary:", counts or "empty")
