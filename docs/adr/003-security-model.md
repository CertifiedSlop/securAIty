# ADR-003: Security Model

## Status

Accepted

## Date

2026-03-26

## Context

The securAIty platform handles sensitive security operations including vulnerability scanning, threat detection, and compliance auditing. The security model must protect:

1. **Confidentiality**: Security findings, vulnerability data, audit results
2. **Integrity**: Agent communications, task results, configuration data
3. **Availability**: Continuous security monitoring and response
4. **Auditability**: Complete audit trail of all security operations

### Threat Model

| Threat | Impact | Mitigation Strategy |
|--------|--------|---------------------|
| Unauthorized API access | Data breach, system compromise | JWT authentication, RBAC |
| Agent impersonation | False results, malicious commands | Mutual TLS, agent certificates |
| Event tampering | Undetected threats, false alerts | Message signing, integrity checks |
| Secret exposure | Credential theft, lateral movement | HashiCorp Vault integration |
| Data leakage | Compliance violations, reputation | Encryption at rest and in transit |
| Denial of service | Security blind spots | Rate limiting, resource quotas |

### Compliance Requirements

- **SOC2**: Access controls, encryption, audit logging
- **ISO27001**: Cryptographic controls, identity management
- **GDPR**: Data protection, access controls
- **PCI DSS**: Encryption, access management, logging

## Decision

We implement a **defense-in-depth security model** with multiple layers:

### Layer 1: Authentication & Authorization

#### API Authentication

```
┌─────────────────────────────────────────────────────────────┐
│                    Authentication Flow                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────────┐  │
│  │  Client  │───▶│   /auth  │───▶│  JWT Access Token    │  │
│  │          │    │  /login  │    │  (expires: 30 min)   │  │
│  └──────────┘    └──────────┘    └──────────────────────┘  │
│       │                                      │              │
│       │                                      ▼              │
│       │                          ┌──────────────────────┐  │
│       │                          │  JWT Refresh Token   │  │
│       │                          │  (expires: 7 days)   │  │
│       │                          └──────────────────────┘  │
│       │                                      │              │
│       └──────────────────────────────────────┘              │
│                          │                                  │
│                          ▼                                  │
│              Use access token for API requests             │
│              Refresh when expired                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Token Structure

```json
{
  "sub": "admin_user",
  "roles": ["admin", "analyst"],
  "permissions": ["read", "write", "delete"],
  "iat": 1711450800,
  "exp": 1711452600,
  "type": "access",
  "jti": "uuid-token-identifier"
}
```

#### Role-Based Access Control (RBAC)

| Role | Permissions | Use Case |
|------|-------------|----------|
| `admin` | Full access | System administrators |
| `analyst` | Read + investigate | Security analysts |
| `auditor` | Read-only + reports | Compliance auditors |
| `agent` | Task execution only | AI agents |
| `viewer` | Read-only (limited) | Stakeholders |

### Layer 2: Secrets Management

#### HashiCorp Vault Integration

```
┌─────────────────────────────────────────────────────────────┐
│                   Secrets Architecture                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              HashiCorp Vault Server                   │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐     │   │
│  │  │  Database  │  │   API      │  │   Agent    │     │   │
│  │  │  Passwords │  │   Keys     │  │  Tokens    │     │   │
│  │  └────────────┘  └────────────┘  └────────────┘     │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐     │   │
│  │  │ Encryption │  │   TLS      │  │   OAuth    │     │   │
│  │  │   Keys     │  │  Certs     │  │  Secrets   │     │   │
│  │  └────────────┘  └────────────┘  └────────────┘     │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ▲                                   │
│                          │                                   │
│         ┌─────────────────┼─────────────────┐               │
│         │                 │                 │               │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐        │
│  │   App       │  │   Agents    │  │  Database   │        │
│  │  Server     │  │             │  │  Clients    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                              │
│  All secrets accessed via Vault API with TTL-based leases  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Secret Access Pattern

```python
from securAIty.security.vault import VaultClient

vault = VaultClient(
    url="http://vault:8200",
    token=os.getenv("VAULT_TOKEN"),
)

# Retrieve secret with automatic renewal
db_password = await vault.get_secret(
    path="secret/database",
    key="password",
)

# Dynamic database credentials
db_creds = await vault.get_dynamic_credentials(
    backend="database",
    role="readonly",
    ttl="1h",
)
```

### Layer 3: Encryption

#### Data Classification

| Classification | Examples | Protection |
|---------------|----------|------------|
| **Restricted** | API keys, passwords, tokens | Encrypt at rest + in transit |
| **Confidential** | Scan results, vulnerability data | Encrypt at rest + in transit |
| **Internal** | Agent status, system metrics | Encrypt in transit |
| **Public** | Health check responses | No encryption required |

#### Encryption Standards

| Data Type | Algorithm | Key Size | Mode |
|-----------|-----------|----------|------|
| Data at rest | AES-256 | 256-bit | GCM |
| Data in transit | TLS 1.3 | N/A | ChaCha20-Poly1305 |
| Passwords | Argon2id | N/A | Memory-hard |
| JWT signing | HMAC-SHA256 | 256-bit | N/A |
| File quarantine | AES-256 | 256-bit | GCM + HMAC |

#### Key Management

```
┌─────────────────────────────────────────────────────────────┐
│                    Key Hierarchy                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │              Master Key (Vault)                     │     │
│  │              (AES-256, HSM-backed)                  │     │
│  └────────────────────┬───────────────────────────────┘     │
│                       │                                      │
│         ┌─────────────┼─────────────┐                       │
│         │             │             │                       │
│  ┌──────▼──────┐ ┌────▼────┐ ┌─────▼─────┐                 │
│  │ Data Key    │ │ API Key │ │ Agent Key │                 │
│  │ (per-tenant)│ │ (JWT)   │ │ (mTLS)    │                 │
│  └─────────────┘ └─────────┘ └───────────┘                 │
│                                                              │
│  Key rotation: 90 days (automated via Vault)                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Layer 4: Network Security

#### Network Segmentation

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Architecture                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Public Network (DMZ)                     │   │
│  │  ┌────────────┐                                      │   │
│  │  │    API     │  Port 8000 (HTTPS)                   │   │
│  │  │  Gateway   │  Port 8222 (NATS Monitoring)         │   │
│  │  └────────────┘                                      │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                    ┌─────▼─────┐                            │
│                    │  Firewall │                            │
│                    └─────┬─────┘                            │
│                          │                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Internal Network (Private)               │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │   │
│  │  │  NATS    │  │ Postgres │  │  Vault   │           │   │
│  │  │  :4222   │  │  :5432   │  │  :8200   │           │   │
│  │  └──────────┘  └──────────┘  └──────────┘           │   │
│  │                                                      │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │   │
│  │  │Antivirus │  │Pentester │  │ Analyst  │           │   │
│  │  │  Agent   │  │  Agent   │  │  Agent   │           │   │
│  │  └──────────┘  └──────────┘  └──────────┘           │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  No direct external access to internal network              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Firewall Rules

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| External | API Gateway | 443 | TCP | HTTPS API |
| API Gateway | NATS | 4222 | TCP | Event bus |
| API Gateway | Postgres | 5432 | TCP | Database |
| Agents | NATS | 4222 | TCP | Event subscription |
| Agents | Vault | 8200 | TCP | Secret retrieval |
| All | Monitoring | 9090 | TCP | Metrics |

### Layer 5: Audit Logging

#### Audit Event Categories

| Category | Events | Retention |
|----------|--------|-----------|
| Authentication | Login, logout, token refresh | 1 year |
| Authorization | Access denied, privilege escalation | 1 year |
| Data Access | Read, write, delete operations | 90 days |
| System | Configuration changes, agent lifecycle | 1 year |
| Security | Threat detection, vulnerability scans | 2 years |

#### Audit Log Schema

```json
{
  "audit_id": "aud_abc123",
  "timestamp": "2026-03-26T10:30:00Z",
  "event_type": "AUTHENTICATION_SUCCESS",
  "actor": {
    "user_id": "usr_xyz",
    "username": "admin",
    "roles": ["admin"]
  },
  "action": "login",
  "resource": "/api/v1/auth/login",
  "outcome": "success",
  "source_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "correlation_id": "corr_def456"
}
```

## Implementation

### Security Middleware

```python
from securAIty.api.middleware.authentication import AuthenticationMiddleware
from securAIty.api.middleware.rate_limit import RateLimitMiddleware

app.add_middleware(
    AuthenticationMiddleware,
    jwt_secret=os.getenv("JWT_SECRET"),
    exclude_paths=["/health", "/ready", "/auth/login"],
)

app.add_middleware(
    RateLimitMiddleware,
    config=RateLimitConfig(
        requests_per_minute=100,
        burst_size=20,
    ),
)
```

### Agent Security

```python
from securAIty.security.agent_auth import AgentAuthenticator

authenticator = AgentAuthenticator(
    ca_cert_path="/etc/ssl/ca.crt",
    agent_cert_path="/etc/ssl/agents/{agent_id}.crt",
    agent_key_path="/etc/ssl/agents/{agent_id}.key",
)

async def verify_agent(agent_id: str, certificate: bytes) -> bool:
    return await authenticator.verify_certificate(agent_id, certificate)
```

### Quarantine Security

```python
from securAIty.agents.antivirus import AntivirusAgent

antivirus = AntivirusAgent(
    quarantine_directory="/var/quarantine/securAIty",
    max_file_size=100 * 1024 * 1024,  # 100MB
)

# Quarantined files are:
# 1. Encrypted with AES-256-GCM
# 2. Stored with restricted permissions (600)
# 3. Accompanied by metadata file
# 4. Original securely deleted (shred)
```

## Consequences

### Positive

1. **Comprehensive Coverage**: Multiple security layers address different attack vectors
2. **Compliance Ready**: Maps to major compliance frameworks
3. **Defense in Depth**: Breach of one layer doesn't compromise system
4. **Audit Trail**: Complete visibility into security operations
5. **Zero Trust**: No implicit trust, verify all requests

### Negative

1. **Complexity**: Multiple security layers increase operational overhead
2. **Performance**: Encryption and validation add latency (~5-10ms per request)
3. **Key Management**: Requires robust key rotation and recovery procedures
4. **Vault Dependency**: System unavailable if Vault is unreachable

### Trade-offs

| Security Control | Alternative | Why Selected |
|-----------------|-------------|--------------|
| **JWT** | Session-based | Stateless, scalable, agent-friendly |
| **Vault** | Environment variables | Dynamic secrets, audit logging, rotation |
| **AES-256-GCM** | AES-256-CBC | Authenticated encryption, no padding oracle |
| **mTLS for agents** | API keys | Mutual authentication, certificate rotation |
| **RBAC** | ABAC | Simpler to understand and audit |

## Security Testing

### Automated Scanning

```bash
# Dependency scanning
make security-scan

# Static analysis
make bandit

# Container scanning
make container-scan

# API security testing
make api-security-test
```

### Penetration Testing

The Pentester agent performs continuous self-assessment:

```python
# Scheduled vulnerability scans
await pentester.vulnerability_scan(
    target={"host": "api.securAIty.local"},
    scope={"ports": "1-65535"},
)

# Exploitation testing (non-destructive)
await pentester.exploitation_test(
    vulnerability_id="vuln_abc123",
    safe_mode=True,
)
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

## Related ADRs

- [ADR-001: Event-Driven Architecture](001-event-driven-architecture.md)
- [ADR-002: Agent Communication Patterns](002-agent-communication-patterns.md)
- [ADR-004: Storage Pattern](004-storage-pattern.md)
