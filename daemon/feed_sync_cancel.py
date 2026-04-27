"""
Cooperative cancel for feed sync scripts.

The web UI touches data/feed_sync_cancel; each sync script checks between
steps and exits with code 10 if the flag was present.

When PHP launches a sync child, it sets FEED_SYNC_CANCEL_PATH to the same
absolute path it uses for touch() so Python never misses the flag due to
symlink / cwd / DATA_DIR resolution differences.
"""

from __future__ import annotations

import os
from pathlib import Path

FILENAME = "feed_sync_cancel"


def cancel_flag_path(data_dir: Path) -> Path:
    env = (os.environ.get("FEED_SYNC_CANCEL_PATH") or "").strip()
    if env:
        return Path(env)
    return data_dir / FILENAME


def cancel_requested(data_dir: Path) -> bool:
    path = cancel_flag_path(data_dir)
    if not path.is_file():
        return False
    try:
        path.unlink()
    except OSError:
        pass
    return True
