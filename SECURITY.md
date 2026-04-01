# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Supply Chain Guard, **please report it privately** rather than opening a public issue.

### Preferred: GitHub Private Vulnerability Reporting

Use GitHub's built-in [private vulnerability reporting](https://github.com/eris-ths/supply-chain-guard/security/advisories/new) to submit your report. This keeps the details confidential until a fix is available.

### Alternative: Email

Contact the maintainer directly at the email associated with the [@eris-ths](https://github.com/eris-ths) GitHub account.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix or mitigation**: Depends on severity, but we aim for 30 days for critical issues

## Scope

The following are in scope for security reports:

- Vulnerabilities in the scan or remediation scripts (`scripts/`)
- False negatives that could give users a false sense of security
- Issues in the SKILL.md that could cause Claude Code to take unintended destructive actions
- Sensitive data exposure risks

The following are **out of scope**:

- Known limitations already documented in [README.md#limitations](README.md#limitations)
- Threats not yet in the Known Threats database (report these as regular Issues)
- Vulnerabilities in third-party tools (npm, osv-scanner, etc.) — report those upstream

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | Yes       |
| < 3.0   | No        |
