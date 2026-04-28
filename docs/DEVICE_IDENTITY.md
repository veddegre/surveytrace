# Device identity (Phase 5)

SurveyTrace stores **addresses** and **devices** separately:

- **`assets`** — one row per discovered **IP** (and therefore per L3 path you can scan). `ip` remains the unique key for host rows.
- **`devices`** — a **stable logical identity** for correlation, reporting, and future merge/split. Every asset row points at `device_id`.

## v1 behavior

1. **New IP** — the scanner creates a new `devices` row, sets `primary_mac_norm` when a valid MAC is known, and inserts the `assets` row with that `device_id`.
2. **Existing IP** — `ON CONFLICT(ip)` updates scan fields; **`device_id` is not changed** on update, so the same IP keeps the same device as long as the row exists.
3. **Legacy data** — migration `migration_device_identity_v1` creates one `devices` row per existing `assets` row with `device_id` null, then sets `device_id` (1:1 backfill).

## Signals (current and future)

- **Routed / L3** — identity is still **IP-led** in v1: the asset row is the unit of scan results.
- **MAC** — stored as `primary_mac_norm` on `devices` (lowercase 12 hex, no separators) when the address is a **link where L2 is trustworthy** (e.g. same broadcast domain). It is a **strong hint** for future deduplication, not a sole primary key.
- **Merge and split** across IPs, hostname changes, or conflicting signals are **out of scope** for v1; the schema is ready to attach more identifiers and policies later.

## API and UI

`GET /api/assets.php` returns `device_id` on list and detail responses (from `a.*` / `decode_asset`). Optional filter **`device_id`** (integer) restricts the list and exports to one logical device.

`GET /api/devices.php` lists devices with aggregate fields (`asset_count`, `last_seen_max`, `ip_sample`) and supports **`?id=N`** for one device plus its linked assets.

The web UI adds a **Devices** tab (browse → **Assets** for a chosen device), **device detail** side panel (click a device id), and shows `device_id` in the **Assets** table, **host detail** panel, **dashboard** top-vulnerable table, and **CSV/JSON export** (`/api/export.php` honors `device_id` when filtering). Assets can be sorted by `device_id`.
