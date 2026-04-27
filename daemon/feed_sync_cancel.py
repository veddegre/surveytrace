"""
Cooperative cancel for feed sync scripts.

The web UI touches data/feed_sync_cancel; each sync script checks between
steps and exits with code 10 if the flag was present.

When PHP launches a sync child, it sets FEED_SYNC_CANCEL_PATH (putenv + inherited
env) to the same absolute path it uses for touch() so Python never misses the flag
due to symlink / cwd / DATA_DIR resolution differences.

We only *test* for the marker file here — do not unlink. PHP clears the flag when
the sync finishes (state_clear) and state_begin clears a stale flag on the next run.
Removing the file on first poll caused races where a check could fire twice
inconsistently or the flag vanished before the process actually exited.
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
    """True if the UI requested stop (marker file exists). Non-destructive."""
    return cancel_flag_path(data_dir).is_file()
