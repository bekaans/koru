# Security Policy

Koru is a security tool, and we take vulnerabilities seriously. This document is the
coordinated disclosure policy for the project.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| Older than 0.1 | No |

Security fixes are released for the latest minor version. Once a newer minor version exists,
the previous one receives critical fixes only. Releases are signed (`SHA256SUMS.sig`);
verification is implemented in `distribution/install.sh` and described in
[ADR-0008](docs/adr/0008-distribution-hardening-signing.md).

## Reporting a vulnerability

If you believe you found a security vulnerability:

1. **Do not open a public issue, pull request or discussion.**
2. Report it privately in one of two ways:
   - GitHub private vulnerability reporting:
     <https://github.com/korusecurity/koru/security/advisories/new>
   - Email: security@korusecurity.com
3. Include:
   - the affected version or commit,
   - a short description of the issue,
   - reproduction steps or evidence (logs, an input file),
   - the estimated impact,
   - a suggested fix, if you have one.

## Secrets in reports

Do not attach real passwords, tokens, private keys or third parties' personal data.
Koru's decoy values are fake; if you saw a real secret, name its location, not the
value. We use what you send only to fix the vulnerability and never share it without
your permission.

## Response times

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| First assessment (accept, reject, or more information requested) | 10 business days |
| Fix or mitigation for a critical vulnerability | 30 days |
| Fix for other vulnerabilities | Next planned release |

We follow coordinated disclosure. We agree on a disclosure date with the reporter, wait at
most 90 days, and publish the details as a GitHub security advisory when the fix is ready or
the window expires. When a fix ships, the reporter is credited in the advisory if they wish.

## Scope

**In scope:** the code in this repository (`crates/`, `xtask/`, `fuzz/`), the
`distribution/` scripts and the systemd unit, the release signature and verification
chain, the `packages/` and `schemas/` data files, and the CI configuration. In
particular: privilege escalation, memory or logic errors in the decoy/rule/config
parsers, signature-verification bypasses, secret leaks, and silently disabling Koru.

**Out of scope:** attacks against a server Koru protects (that is Koru's detection
scope), vulnerabilities in Pulsar and other dependencies (report them to the
respective project; tell us too if Koru is affected), the known limits of an attacker
who already has root ([threat model](docs/threat-model.md)), social engineering, and resource-exhausting
denial-of-service load tests.

Known limits and open risks are tracked in [`docs/threat-model.md`](docs/threat-model.md).

## Safe research

When doing good-faith security research, work only against your own installation, do
not access other people's data, and do not disrupt the service. We take no legal
action against researchers who follow these rules.
