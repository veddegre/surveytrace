# Device identity

## Who this is for

This document is for:

- advanced operators working with asset correlation
- developers extending SurveyTrace data models
- anyone troubleshooting identity, merging, or deduplication

If you are only running scans and reviewing assets, you may not need this level of detail.

---

## Overview

SurveyTrace separates **addresses** and **devices** to support accurate correlation and reporting.

- **`assets`** — one row per discovered **IP address** (an L3 scan target).  
  The `ip` field remains the unique key for each asset.

- **`devices`** — a **logical system identity** that groups one or more assets.  
  Each asset references a device using `device_id`.

### Key idea

```text
Asset = IP address
Device = logical system
```

A single device may have multiple IPs, and therefore multiple asset rows.

---

## Behavior

### New IP

- A new `devices` row is created.
- `primary_mac_norm` is set when a valid MAC is available.
- The new `assets` row is created with that `device_id`.

---

### Existing IP

- `ON CONFLICT(ip)` updates scan-related fields.
- **`device_id` is not changed** during updates.
- This ensures identity stability for a given IP over time.

---

### Existing data

- When device identity is introduced into an existing dataset:
  - a `devices` row is created for each asset lacking `device_id`
  - assets are updated to reference those devices (1:1 backfill)

---

## Identity signals

SurveyTrace uses multiple signals to represent identity.

### IP (primary signal)

- Identity is **IP-led**
- Each scan result is tied to an asset (IP)
- This is the authoritative unit for scan data

---

### MAC address

- Stored as `primary_mac_norm` on `devices`
- Format: lowercase, 12 hex characters, no separators

Used when:

- the MAC is observed in a **trusted L2 context**
  - e.g., same broadcast domain

Role:

- strong correlation hint
- **not a unique identifier**

---

## Device operations

### Merge (supported)

- Combine multiple devices into one logical identity
- All linked assets are reassigned to the survivor

Use cases:

- duplicate detection
- multi-IP systems identified post-scan
- correcting matching errors

---

### Split (not currently supported)

- Separating one device into multiple identities is not available
- If needed, create new assets and reassign manually

---

## API behavior

### Assets

`GET /api/assets.php`

- Returns `device_id` in list and detail responses
- Supports filtering:

```text
?device_id=<id>
```

---

### Devices

`GET /api/devices.php`

- Lists devices with aggregate fields:
  - `asset_count`
  - `last_seen_max`
  - `ip_sample`

- Supports:

```text
?id=<id>
```

to retrieve a single device with linked assets

---

### Merge operation

`POST /api/devices.php`

```json
{
  "action": "merge",
  "survivor_id": N,
  "merge_ids": [a, b, ...]
}
```

Behavior:

- Moves all `assets.device_id` to `survivor_id`
- Deletes merged `devices` rows (limit: 50 per request)
- Promotes `primary_mac_norm` if the survivor does not have one
- Updates `updated_at` on the survivor
- Writes an `INFO` entry to `scan_log` (no job_id)

Requires authentication consistent with other write APIs.

---

## UI behavior

### Devices view

- Dedicated **Devices** tab
- Browse devices and pivot into associated assets

---

### Asset search

- Single search field:
  - text → hostname / asset match
  - numeric + Enter → filters by `device_id`
- Search clears automatically after numeric filter

---

### Device detail panel

- Accessible by clicking a device ID
- Shows:
  - linked assets
  - summary information
- Includes **Merge…** action with confirmation

---

### Visibility across UI

`device_id` is shown in:

- Assets table
- Host detail panel
- Dashboard (top vulnerable assets)
- Export outputs (CSV / JSON)

Exports via:

```text
/api/export.php
```

respect the `device_id` filter.

---

### Sorting

- Assets can be sorted by `device_id`

---

## Design principles

- **Stability** — asset-to-device relationships are not implicitly changed
- **Operator control** — merging requires explicit action
- **Separation** — scan data (assets) and identity (devices) are distinct
- **Clarity** — identity changes are visible and auditable

---

## When this matters

You will interact with device identity when:

- identifying duplicate systems
- working with multi-IP hosts
- analyzing asset relationships
- performing cleanup or normalization

---

See also:
- [Concepts](wiki/concepts.md)
- [Reporting](wiki/reporting.md)