# API Keys

[← Back to Documentation](README.md)

## Where API keys are used

- External AI providers (when configured)
- Integration endpoints that require authenticated outbound or pull access
- Feed and connector features that rely on third-party services

## How to configure keys

- Configure keys in the appropriate Settings/Integrations screens.
- Use environment variables where supported for operational separation.
- Keep configuration consistent across service restarts/deploys.

## Security considerations

- Treat keys as secrets.
- Do not commit keys to git or plaintext config in shared repos.
- Use least-privilege keys scoped to required APIs only.
- Restrict access to hosts/users that need operational control.

## Rotation and updates

- Rotate keys on a schedule and after any suspected exposure.
- Update keys in SurveyTrace settings/integration config.
- Verify connectivity/status after rotation (sync/test action where available).

---

See also:
- [Documentation home](README.md)

---
