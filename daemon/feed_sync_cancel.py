"""
Cooperative cancel for feed sync scripts.

The web UI touches data/feed_sync_cancel; each sync script checks between
steps and exits with code 10 if the flag was present.
"""

from __future__ import annotations

from pathlib import Path

FILENAME = "feed_sync_cancel"


def cancel_requested(data_dir: Path) -> bool:
    path = data_dir / FILENAME
    if not path.is_file():
        return False
    try:
        path.unlink()
    except OSError:
        pass
    return True
