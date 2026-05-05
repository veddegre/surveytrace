# SurveyTrace Documentation

This directory contains documentation for both **operators** and **developers**.

---

## Start here

- [Wiki (operator documentation)](wiki/README.md)  
  Guides for installing, operating, and troubleshooting SurveyTrace.

---

## Operator documentation (wiki)

Located in `docs/wiki/`

Use this if you are:

- installing SurveyTrace
- running scans
- working with enrichment (Zabbix, AI, etc.)
- generating reports
- troubleshooting issues

Key entry point:

- [Wiki home](wiki/README.md)

---

## Advanced / internal documentation

These documents describe how SurveyTrace works internally or how to extend it.

### Device identity

- [Device identity](DEVICE_IDENTITY.md)

Explains how SurveyTrace separates:

- assets (IP-level)
- devices (logical systems)

Includes:

- identity model
- merge behavior
- API and UI behavior

---

### Connector development guide

- [Connector development guide](CONNECTOR_DEVELOPMENT_GUIDE.md)

Defines the standard pattern for building integrations:

- external data ingestion
- normalization and caching
- asset linking
- API and UI exposure

Use this when adding or modifying connectors.

---

## How to use this documentation

- New users → start with the **wiki**
- Daily operators → use **wiki workflows**
- Troubleshooting → use **wiki troubleshooting**
- Developers → use **internal docs**

---

## Documentation structure

```text
docs/
  README.md                      ← this file
  DEVICE_IDENTITY.md             ← system design (identity model)
  CONNECTOR_DEVELOPMENT_GUIDE.md ← integration pattern guide
  wiki/                          ← operator documentation
    README.md
    getting-started.md
    scanning.md
    enrichment.md
    reporting.md
    ...
```

---

## Notes

- The wiki is **task-focused and operator-oriented**
- The root docs are **system and developer references**
- Both are maintained together to ensure consistency across the platform