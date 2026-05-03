# Starter integrations content

This directory is copied to **`/opt/surveytrace/integrations-starter/`** on master deploy (`deploy.sh`) for convenience; it also lives in the repo for packaging into Splunk / Grafana manually.

| Subfolder | Contents |
|-----------|----------|
| **`splunk_surveytrace/`** | Splunk app skeleton (dashboards, saved searches, props for **`surveytrace:reporting:event`**). |
| **`grafana/`** | Infinity starter dashboard JSON + setup README. |

See the main **`README.md`** → *Integrations (push and pull)* for HTTP endpoint summaries and token usage.
