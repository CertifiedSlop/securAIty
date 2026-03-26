# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of securAIty seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

- **Email**: security@securAIty.local (if configured)
- **GitHub Security Advisories**: Use the "Report a vulnerability" feature in the Security tab

### What to Include

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Affected versions
- Any potential impact
- Suggested fix (if available)

### Response Timeline

- **Acknowledgment**: Within 48 hours of your report
- **Status Update**: Within 5 business days
- **Resolution Target**: Based on severity
  - Critical: 24-72 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: 4 weeks

### Disclosure Policy

- We will notify you when the vulnerability is fixed
- We request a 90-day embargo period before public disclosure
- We will credit you for the discovery (unless you prefer to remain anonymous)

## Security Measures

### Code Security

- All dependencies are regularly scanned for vulnerabilities
- Static code analysis is performed on every commit
- Security-focused code reviews are mandatory

### Infrastructure Security

- Secrets are managed through HashiCorp Vault
- All communications are encrypted (TLS 1.3+)
- Network segmentation is enforced via Docker networks

### Agent Security

- Agents run with minimal required privileges
- Agent actions are logged and auditable
- Agent communications are authenticated and encrypted

### Data Security

- Sensitive data is encrypted at rest
- Data in transit uses TLS encryption
- Automatic data retention and deletion policies

## Security Best Practices for Contributors

### Code Contributions

1. Never commit secrets or credentials
2. Use parameterized queries to prevent SQL injection
3. Validate and sanitize all inputs
4. Implement proper access controls
5. Log security-relevant events

### Dependencies

1. Keep dependencies up to date
2. Review security advisories for dependencies
3. Minimize the number of dependencies
4. Use pinned versions for reproducibility

### Testing

1. Include security tests in your test suite
2. Test for common vulnerabilities (OWASP Top 10)
3. Verify access controls in integration tests
4. Include fuzzing for input validation

## Vulnerability Scoring

We use CVSS v3.1 for vulnerability scoring:

| Score Range | Severity   | Response Time |
| ----------- | ---------- | ------------- |
| 9.0-10.0    | Critical   | 24-72 hours   |
| 7.0-8.9     | High       | 1 week        |
| 4.0-6.9     | Medium     | 2 weeks       |
| 0.1-3.9     | Low        | 4 weeks       |

## Security Updates

Security updates are announced through:

- GitHub Security Advisories
- Release notes
- Security mailing list (if configured)

## Contact

For security-related questions not covered by vulnerability reports, please open a regular GitHub issue with the "security" label.

---

**Last Updated**: March 26, 2026
