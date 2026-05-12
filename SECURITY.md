# Security Policy

CAI is a defensive security platform. Because it orchestrates active vulnerability scanners, a flaw in CAI can have outsized impact (e.g., scanning out-of-scope targets, leaking findings, bypassing the LLM PII scrubber). We take reports seriously and prioritize coordinated disclosure.

## Supported versions

CAI is in **alpha** (pre-1.0). Only the `main` branch is supported for security fixes. Pinned-version users are encouraged to upgrade.

| Version | Supported          |
|---------|--------------------|
| `main`  | :white_check_mark: |
| < 1.0   | :x: (use `main`)   |

## Reporting a vulnerability

**Please do NOT open a public GitHub issue for security reports.**

Use one of the following private channels:

1. **Preferred** — [GitHub Security Advisories](https://github.com/roqueribeiro/more4cai/security/advisories/new) (private to maintainers; coordinated-disclosure workflow built in)
2. **Backup** — open a private "Draft Advisory" via the same page, or contact a maintainer listed in [`MAINTAINERS.md`](MAINTAINERS.md) (when present) via the email on their GitHub profile

Include the following whenever possible:

- A description of the issue and the attack scenario it enables
- The affected component (adapter name, API endpoint, module path)
- A minimal reproduction (PoC) — ideally against the bundled `lab` profile (Juice Shop / DVWA / WebGoat)
- Your suggested CVSS v3.1 vector (we will reassess)
- Whether you would like credit, and under what name/handle

## Scope

**In scope:**

- The `orchestrator/` Python package (API, adapters, AI gateway, audit log, scrubber, persistence, reporting)
- The Docker images we build in `docker/images/`
- The default `compose.yml` configuration (RCE/SSRF/auth bypass/etc.)
- The AI Fix Bundle JSON schema (deserialization risks, prompt-injection vectors)

**Out of scope:**

- Vulnerabilities in upstream scanners (Nmap, ZAP, Nuclei, Trivy, Greenbone, ...) — report those to the upstream project
- Vulnerabilities in the `lab` profile targets (Juice Shop, DVWA, WebGoat) — these are intentionally vulnerable
- Findings produced by CAI scans against third-party systems (those belong to those systems' owners)
- Social-engineering, physical, or DoS attacks against project infrastructure
- Issues that require a fully privileged local user or a compromised host

## Our commitment

| Stage           | SLA                                        |
|-----------------|--------------------------------------------|
| Acknowledgement | within 72 hours                            |
| Triage          | within 7 days                              |
| Fix or mitigation | within 90 days (extendable by mutual agreement) |
| Public disclosure | coordinated with the reporter; default 90 days from acknowledgement |

We will keep you updated and, unless you prefer otherwise, credit you in the [`CHANGELOG.md`](CHANGELOG.md) and the published advisory.

## Safe harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to comply with this policy
- Avoid privacy violations, destruction of data, and disruption of services
- Do not exfiltrate data beyond what is necessary to demonstrate impact
- Give us a reasonable window to remediate before any public disclosure

If in doubt, ask first.

## Hardening guidance for operators

CAI ships with safe defaults for a lab/dev environment. Before running against real assets, operators should:

- Set `LAB_ONLY=false` only after configuring `TARGET_ALLOWLIST`
- Set `REQUIRE_AUTH_REF=true` to force an `authorization_ref` on every scan
- Rotate `APP_TOKEN`, `ZAP_API_KEY`, `POSTGRES_PASSWORD` away from the `changeme-*` defaults
- Never expose the orchestrator on `0.0.0.0`; keep it bound to `127.0.0.1` behind a TLS reverse proxy
- Confirm `scrubber.py` is enabled before sending findings to external LLM providers
- Review the threat model in [`docs/threat-model.md`](docs/threat-model.md)
