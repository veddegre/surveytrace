# Sample advisory JSON (validation / labs)

These files ship under **`docs/samples/`** with **`deploy.sh` / `setup.sh`** so an install tree at **`/opt/surveytrace/docs/samples/`** has bounded payloads for operator checks.

| File | Purpose |
|------|---------|
| `nvd_metadata.sample.json` | Feed **`scripts/import_nvd_metadata.php`** — CVE metadata + references only (`package_authority` stays **metadata_only**; no package rules). |
| `distro_advisories.sample.json` | Feed **`scripts/import_distro_advisories.php`** — minimal Ubuntu/Debian-style `fixed_version` + `distro_release` vendor rules (single advisory). |
| `ubuntu_intermediate.sample.json` | **Intermediate** format for **`scripts/convert_ubuntu_advisories.php`** (`surveytrace_ubuntu_intermediate_v1`) → normalized import JSON. |
| `ubuntu_oval_fragment.xml` | Tiny **Ubuntu CVE OVAL** fragment for **`convert_ubuntu_advisories.php --format=oval`** tests and operator smoke checks. |
| `ubuntu_production.sample.json` | Feed **`scripts/import_distro_advisories.php`** — realistic multi-CVE Ubuntu advisory payload with multiple packages, releases, and severity levels. |
| `advisory_cve_test.sample.json` | Feed **`scripts/import_advisories.php`** — internal **`CVE-TEST-*`** style row for correlation / **`remove_advisory.php`** drills. |

**Cleanup:** Do **not** leave **`CVE-TEST-*`** or other lab advisories in production databases. After validation, run **`php scripts/remove_advisory.php --advisory-key=CVE-TEST-0001 --apply`** (dry-run first; optional **`--source=internal`** guard). Vendor rows require **`--force`** — see [Vulnerability advisory operator runbook](../wiki/vulnerability-advisory-runbook.md).

The same JSON also lives under **`data/samples/`** in the git checkout (`setup.sh` / `deploy.sh` **exclude** copying `data/` from the repo, so prefer **`docs/samples/`** paths on installed masters).
