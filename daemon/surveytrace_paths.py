"""
SurveyTrace install paths for Python daemons (match api/db.php).

- ST_DATA_DIR  ≈ dirname(api) + '/data'  →  <install_root>/data
- ST_DB_PATH   ≈ <install_root>/data/surveytrace.db

Environment (set in systemd for a stable layout regardless of symlinks):
  SURVEYTRACE_INSTALL_DIR — install root (e.g. /opt/surveytrace)
  SURVEYTRACE_DB_PATH     — full path to surveytrace.db (overrides INSTALL_DIR)
"""

from __future__ import annotations

import os
from pathlib import Path


def install_root() -> Path:
    inst = (os.environ.get("SURVEYTRACE_INSTALL_DIR") or "").strip()
    if inst:
        return Path(inst).expanduser().resolve()
    # daemon/surveytrace_paths.py → daemon/ → install root
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    return install_root() / "data"


def main_db_path() -> Path:
    raw = (os.environ.get("SURVEYTRACE_DB_PATH") or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return data_dir() / "surveytrace.db"
