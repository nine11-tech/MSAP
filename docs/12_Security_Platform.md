# Security Platform Operations and Static-Analysis Scope

## Authentication and session security

MSAP is an internal platform with no public registration. Django authenticates
the built-in User model and stores server-side sessions. DRF uses session
authentication and Django CSRF; the React client includes credentials and sends
the CSRF header for unsafe methods. Production defaults use an HttpOnly,
eight-hour `msap_sessionid` cookie with Secure and SameSite=Lax, secure CSRF
cookies, HSTS, content-type sniffing protection, frame denial, and a same-origin
referrer policy.

django-axes records login attempts in the shared metadata database. Five failures
lock the username/source-IP combination for fifteen minutes by default. Deploy
behind a reverse proxy only with `MSAP_TRUST_PROXY_HEADERS=true`,
`AXES_IPWARE_PROXY_COUNT` set to the exact hop count, and
`AXES_IPWARE_PROXY_TRUSTED_IPS` set to infrastructure-controlled proxies. The
edge proxy must replace, not append to, untrusted forwarding headers.

## Role matrix

| Capability | Admin | Analyst | Viewer |
|---|---:|---:|---:|
| Read projects, audits, results, evidence, reports | Yes | Yes | Yes |
| Create/update projects and audits | Yes | Yes | No |
| Upload APKs and start analysis | Yes | Yes | No |
| Delete platform metadata | Yes | No | No |
| User/group administration | Yes | No | No |
| Detailed deployment/status metadata | Yes | No | No |

Run `python manage.py bootstrap_roles` after migrations. It is idempotent and
does not create users. In Kubernetes, the migration Job runs it automatically.
Create an administrator with a one-shot backend pod or:

```bash
kubectl exec -n msap deployment/msap-backend -- python manage.py createsuperuser
```

## Live component status

Authenticated clients poll `/api/system/status/` every five seconds while the
tab is visible. Results are cached for approximately five seconds. Checks cover
the API, PostgreSQL, Redis, Celery workers, MinIO and required buckets, analyzer
capabilities, and both framework catalogs. Dependency checks have short
timeouts. Viewer responses contain sanitized state; administrator responses may
include counts, application version, and deployment mode. Credentials,
connection strings, sensitive hostnames, and raw exceptions are never returned.

## Deterministic static analysis

The worker validates ZIP paths, symlinks, encryption, entry count, entry size,
aggregate expansion, compression ratio, APK size, and manifest presence before
inspection. Temporary downloads are checksum-verified when a digest is
available and removed after the analyzer scope. APK code and bundled scripts are
never executed, and analysis performs no APK-originated network access.

Normalized artifacts cover APK/manifest metadata, permissions, components,
network-security configuration, signing and certificates, DEX metadata,
bounded code references, redacted secret matches, crypto/WebView references,
native libraries, probable third-party dependency inventory, URLs, package
content, and resilience signals. Full decompiled source and full DEX string
tables are not placed in PostgreSQL. Optional JADX, apktool, APKiD, YARA, and
LIEF capabilities remain disabled/unavailable unless deliberately packaged;
their absence skips capability-specific coverage rather than failing the audit.

## Framework methodology and limitations

The repository owns versioned MASVS and ATT&CK Mobile catalogs and provenance in
`rules/framework_metadata.yaml`. `validate_rules` rejects missing metadata,
duplicate internal IDs, and malformed framework IDs. Catalog updates are manual
and runtime analysis never depends on internet access.

MASVS evaluations record PASS, FAIL, REVIEW_REQUIRED, NOT_APPLICABLE, or
NOT_EVALUATED. Only FAIL creates a vulnerability finding. Missing artifacts or
failed analyzers produce NOT_EVALUATED, never PASS. Compliance reports evaluated,
applicable, and unevaluated counts and warns on partial coverage.

ATT&CK Mobile results are capability-oriented triage signals. A permission,
component, native library, or API reference does not prove that a technique was
executed. Every matched indicator requires contextual/manual validation and is
explicitly labeled “Triage signal — not a malware verdict.” ATT&CK indicators
are excluded from the vulnerability risk score.

Secret evidence contains hashes, counts, and redaction metadata only. Generic
entropy, cryptographic API, WebView, native-hardening, and privacy-purpose
signals normally require manual validation. Static analysis cannot observe
runtime control flow, server-side behavior, dynamically retrieved code,
environmental TLS behavior, or actual user-data access. MSAP therefore does not
claim complete OWASP compliance, complete ATT&CK detection, or malware
classification.
