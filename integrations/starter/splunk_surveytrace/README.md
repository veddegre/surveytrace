# SurveyTrace Splunk starter app

Minimal Splunk Technology Add-On style layout for HEC / JSON events that match **`surveytrace.reporting.event.v1`**.

## Install

1. Copy the `splunk_surveytrace` folder to `$SPLUNK_HOME/etc/apps/` (rename to `splunk_surveytrace` or keep as-is; the Splunk app folder name becomes the app id).
2. Restart Splunk: `splunk restart`.
3. Set the **macro** `surveytrace_index` to your index / sourcetype (Splunk **Settings → Advanced search → Search macros**, or edit `local/macros.conf`):

   ```
   definition = index=main sourcetype=surveytrace:reporting:event
   ```

4. Configure **HTTP Event Collector** with JSON; set **Sourcetype** to `surveytrace:reporting:event` (or override the macro). Send the **canonical event object** (the inner JSON body), not only the Splunk `time` wrapper, if your forwarder already unwraps `event`.

## Sourcetype

Use **`surveytrace:reporting:event`** so `props.conf` applies `KV_MODE = json`. Ingested objects should match **`surveytrace.reporting.event.v1`** (see SurveyTrace **`api/lib_reporting_event_model.php`**): e.g. **`schema_version`**, **`event_id`**, **`source`**, **`occurred_at`**, **`event_type`**, **`severity`**, nested **`scope`**, **`subject`**, **`data_plane`**, **`payload`**. Dashboards and saved searches use **`spath`** on these paths (e.g. **`event_type`**, **`scope.scope_id`**, **`subject.job_id`**).

## Dashboards

Classic Simple XML views under `default/data/ui/views/`. Tune saved search time ranges and the `surveytrace_index` macro for your environment.

## Security

Do not index raw Splunk HEC tokens. SurveyTrace never returns integration pull tokens in admin list APIs; treat HEC URLs and SurveyTrace pull tokens as secrets in Splunk passwords / macros.
