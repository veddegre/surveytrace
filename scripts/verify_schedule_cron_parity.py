#!/usr/bin/env python3
"""
Regression: PHP api/schedule_cron.php next_run must match daemon/scheduler_daemon.py.

Run from any cwd:  python3 scripts/verify_schedule_cron_parity.py
Requires: python3 with zoneinfo, php in PATH.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _php_next_run(cron: str, tz: str, after_utc_naive: str) -> str:
    req = json.dumps(str(ROOT / "api" / "schedule_cron.php"))
    code = f"""require {req};
echo st_schedule_next_run_utc_naive(
    {json.dumps(cron)},
    {json.dumps(tz)},
    new DateTimeImmutable({json.dumps(after_utc_naive)}, new DateTimeZone("UTC"))
);
"""
    proc = subprocess.run(
        ["php", "-r", code],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"php failed (rc={proc.returncode}): {proc.stderr.strip() or proc.stdout}"
        )
    return proc.stdout.strip()


def main() -> int:
    sys.path.insert(0, str(ROOT / "daemon"))
    import scheduler_daemon as sd  # noqa: E402

    cases: list[tuple[str, str, str, str]] = [
        # cron, tz, after UTC naive, description
        ("0 9 * * *", "America/New_York", "2026-05-01 12:00:00", "daily 9am Eastern"),
        ("@daily", "UTC", "2026-05-01 12:00:00", "preset @daily"),
        ("*/15 * * * *", "Europe/Berlin", "2026-01-15 10:07:00", "15-minute step"),
        ("0 0 1 * *", "UTC", "2026-03-15 00:00:00", "monthly 1st"),
        ("0 0 * * 0", "UTC", "2026-05-06 12:00:00", "Sunday weekly (cron 0=Sun)"),
        ("@hourly", "Not/A_Valid_Zone", "2026-06-01 05:30:00", "invalid TZ -> UTC both sides"),
    ]

    failed = 0
    for cron, tz, after_s, label in cases:
        after = datetime.strptime(after_s, "%Y-%m-%d %H:%M:%S")
        py_dt = sd.next_cron_run(cron, after, tz)
        py_s = py_dt.strftime("%Y-%m-%d %H:%M:%S")
        try:
            ph_s = _php_next_run(cron, tz, after_s)
        except Exception as e:
            print(f"FAIL {label}: PHP error: {e}")
            failed += 1
            continue
        if ph_s != py_s:
            print(
                f"FAIL {label}: cron={cron!r} tz={tz!r} after={after_s!r}\n"
                f"  Python: {py_s}\n"
                f"  PHP:    {ph_s}"
            )
            failed += 1
        else:
            print(f"ok  {label}: {py_s}")

    if failed:
        print(f"\n{failed} case(s) failed.", file=sys.stderr)
        return 1
    print(f"\nAll {len(cases)} parity checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
