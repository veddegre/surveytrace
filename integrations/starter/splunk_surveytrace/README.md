# SurveyTrace Splunk starter app

Minimal Splunk Technology Add-On style layout for **`surveytrace.reporting.event.v1`** events: HEC ingest, saved searches, dashboards, and an **optional scripted input** that pulls JSONL from SurveyTrace’s **`json_events_pull`** API.

## Install

1. Copy the `splunk_surveytrace` folder to `$SPLUNK_HOME/etc/apps/` (the folder name should match **`[package] id`** in `default/app.conf`, i.e. **`splunk_surveytrace`**).
2. Restart Splunk: `splunk restart`.
3. Set the **macro** `surveytrace_index` to your index / sourcetype (**Settings → Advanced search → Search macros**, or `local/macros.conf`):

   ```
   definition = index=main sourcetype=surveytrace:reporting:event
   ```

4. For **HEC**: configure HTTP Event Collector with JSON; set **Sourcetype** to **`surveytrace:reporting:event`** (or override the macro). Send the **canonical event object** (the inner JSON body), not only the Splunk `time` wrapper, if your forwarder already unwraps `event`.

## Scripted input — SurveyTrace JSONL pull

Use this when you want Splunk to **poll** SurveyTrace instead of (or in addition to) HEC push.

### Files

| Path | Role |
|------|------|
| **`bin/surveytrace_events.py`** | Python 3 script: reads config, calls **`/api/integrations_events.php?since=…&format=jsonl`** with **`Authorization: Bearer`**, prints JSONL to **stdout**, maintains a checkpoint. |
| **`default/inputs.conf`** | Scripted input stanza (**disabled** by default). Path must match where the app is installed. |
| **`default/surveytrace_pull.ini.example`** | Copy to **`local/surveytrace_pull.ini`** and set **`base_url`** + **`bearer_token`**. |
| **`default/props.conf`** | Sourcetype **`surveytrace:reporting:event`** — `KV_MODE=json`, line-based. |
| **`default/data/ui/nav/default.xml`** | Nav link to starter dashboard. |
| **`default/data/ui/views/surveytrace_overview.xml`** | Simple overview dashboard using the macro. |

### Why `local/surveytrace_pull.ini`?

Splunk scripted inputs do not pass long secrets safely through the stanza alone. The script reads **`$SPLUNK_HOME/etc/apps/splunk_surveytrace/local/surveytrace_pull.ini`** (via path relative to the app: **`../local/surveytrace_pull.ini`** from `bin/`). Restrict file permissions on the indexer (e.g. owner **splunk**, mode **600**).

Example **`local/surveytrace_pull.ini`**:

```ini
[pull]
base_url = https://surveytrace.example.com
bearer_token = st_int_...your_json_events_pull_token...
initial_lookback_hours = 24
# checkpoint_dir =   # optional; default: $SPLUNK_HOME/var/lib/splunk/modinputs/surveytrace/
```

Create a **`json_events_pull`** integration in SurveyTrace **Integrations**, then **Generate / Rotate token** and paste the bearer value here.

### Enable the input

1. Copy **`default/surveytrace_pull.ini.example`** to **`local/surveytrace_pull.ini`**, set **`base_url`** and **`bearer_token`**, fix permissions.
2. Optionally copy the scripted stanza from **`default/inputs.conf`** into **`local/inputs.conf`** so you can set **`disabled = 0`**, **`interval`**, **`index`**, and adjust the **`script://`** path if your app directory name differs.
3. Ensure the script is executable: `chmod +x $SPLUNK_HOME/etc/apps/splunk_surveytrace/bin/surveytrace_events.py`.
4. **`splunk restart`** or reload inputs.

**`default/inputs.conf`** stanza (path must match the real file location):

```ini
[script://$SPLUNK_HOME/etc/apps/splunk_surveytrace/bin/surveytrace_events.py]
disabled = 1
interval = 300
index = main
sourcetype = surveytrace:reporting:event
```

Example **`local/inputs.conf`** override:

```ini
[script://$SPLUNK_HOME/etc/apps/splunk_surveytrace/bin/surveytrace_events.py]
disabled = 0
interval = 300
index = surveytrace
sourcetype = surveytrace:reporting:event
```

### Checkpointing

By default the script stores **`last_since.txt`** under **`$SPLUNK_HOME/var/lib/splunk/modinputs/surveytrace/`** (override with **`checkpoint_dir`** in the INI). The file holds the next **`since`** value (UTC ISO8601). On first run, if no checkpoint exists, the script uses **now minus `initial_lookback_hours`** (default **24**). After each successful fetch, the checkpoint advances from the latest **`occurred_at`** in the JSONL (bumped by one second to limit overlap with inclusive **`since`** on the server). If the response body is empty, the checkpoint is left unchanged so the next run retries the same window.

### Security

- The script does **not** print the token or full request URLs containing secrets.
- Errors are redacted if the token appears in a message.
- Prefer **`Authorization: Bearer`** (the script does not use **`?token=`**).

## Sourcetype

Use **`surveytrace:reporting:event`** so `props.conf` applies **`KV_MODE = json`**. Ingested objects should match **`surveytrace.reporting.event.v1`** (see SurveyTrace **`api/lib_reporting_event_model.php`**): e.g. **`schema_version`**, **`event_id`**, **`source`**, **`occurred_at`**, **`event_type`**, **`severity`**, nested **`scope`**, **`subject`**, **`data_plane`**, **`payload`**. Dashboards and saved searches use **`spath`** on these paths (e.g. **`event_type`**, **`scope.scope_id`**, **`subject.job_id`**).

## Dashboards

Classic Simple XML views under **`default/data/ui/views/`**. Tune saved search time ranges and the **`surveytrace_index`** macro for your environment.

## Security (general)

Do not index raw Splunk HEC tokens or SurveyTrace bearer tokens in log files. SurveyTrace never returns pull token hashes or push secrets in admin list APIs; treat HEC URLs and SurveyTrace tokens as secrets.
