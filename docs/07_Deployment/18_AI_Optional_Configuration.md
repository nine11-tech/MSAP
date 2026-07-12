# AI Optional Configuration - MSAP

## Optional Kimi AI Configuration

Kimi AI support is an optional V1.1 configuration for AI-assisted triage and reporting. It is not required for MSAP V1 analysis, scoring, dashboard or reporting.

## Disabled-by-Default Behavior

The default configuration is:

```env
AI_ASSISTANT_ENABLED=false
```

When disabled, no Kimi API calls are made and all deterministic local workflows continue to work.

## Environment Variables

```env
AI_ASSISTANT_ENABLED=false
AI_PROVIDER=kimi
KIMI_API_KEY=
KIMI_MODEL=
AI_REDACTION_ENABLED=true
AI_MAX_FINDINGS_CONTEXT=
AI_TIMEOUT_SECONDS=
```

## API Key Security

Kimi API keys must be provided through local environment configuration or a local secret manager. They must not be hardcoded in source code, committed to Git or printed in logs.

## No Secret in Git

`.env` files containing real API keys must remain outside version control. Example configuration files should contain empty placeholders only.

## No Logging of API Keys

Request logs, error logs and audit logs must never include `KIMI_API_KEY` or authorization headers.

## Proxy and Network Considerations

Institutions may require an approved proxy, outbound allow-list or network review before enabling Kimi AI. If network access is blocked, MSAP remains functional in no-AI mode.

## Offline / No-AI Fallback

No-AI mode supports APK upload, static analysis, evidence, MASVS results, ATT&CK Mobile triage, scoring and report generation without external services.

## Institutional Approval Requirement

Because Kimi AI is an external service, enabling it requires institutional approval for data handling, provider terms, network access and audit logging.

## Local-First Compatibility

MSAP remains local-first because the deterministic core does not require AI. Optional AI uses only redacted, minimized post-analysis context and never sends raw APKs or full decompiled source code.
