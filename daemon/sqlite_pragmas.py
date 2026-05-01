"""
Shared SQLite PRAGMAs for surveytrace.db (master + collectors).

Keeps WAL, writer-wait, and read-side tuning aligned across scanner, scheduler,
ingest, and sync scripts so PHP + Python processes contend less on busy_timeout.
"""

from __future__ import annotations

import os
import sqlite3

_DEFAULT_BUSY_MS = 60000
_DEFAULT_MMAP = 67108864  # 64 MiB; set SURVEYTRACE_SQLITE_MMAP_BYTES=0 to disable


def apply_surveytrace_pragmas(conn: sqlite3.Connection) -> None:
    """WAL + long busy wait + optional mmap. Writer duration is still bounded by batch commits in callers."""
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        busy = int(os.environ.get("SURVEYTRACE_SQLITE_BUSY_TIMEOUT_MS", str(_DEFAULT_BUSY_MS)))
    except ValueError:
        busy = _DEFAULT_BUSY_MS
    busy = max(1000, min(600000, busy))
    conn.execute(f"PRAGMA busy_timeout={busy}")
    conn.execute("PRAGMA synchronous=NORMAL")
    raw = os.environ.get("SURVEYTRACE_SQLITE_MMAP_BYTES", str(_DEFAULT_MMAP)).strip()
    if raw != "0":
        try:
            n = int(raw)
        except ValueError:
            n = _DEFAULT_MMAP
        if n > 0:
            conn.execute(f"PRAGMA mmap_size={n}")
