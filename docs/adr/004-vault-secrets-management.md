# ADR-004: HashiCorp Vault for Secrets Management

**Date**: 2026-03-26  
**Status**: Accepted  
**Authors**: securAIty Team  

## Context

The securAIty platform requires secure management of sensitive credentials, API keys, encryption keys, and other secrets. Traditional approaches (environment variables, config files) present security risks:

- Secrets in version control
- No audit trail for secret access
- Difficult secret rotation
- No fine-grained access control
- Secrets exposed in process listings
- No lease-based temporary credentials

### Requirements

1. **Secure Storage**: Encrypted storage for all secrets
2. **Access Control**: Fine-grained permissions for secret access
3. **Audit Logging**: Complete audit trail for compliance
4. **Secret Rotation**: Automated and manual rotation support
5. **Dynamic Secrets**: On-demand credential generation
6. **Lease Management**: Time-limited secret access
7. **High Availability**: Cluster mode for production

## Decision

We will use **HashiCorp Vault** as the centralized secrets management solution for securAIty.

### Architecture

```mermaid
graph TB
    subgraph "securAIty Application"
        A[API Server]
        B[Agents]
        C[Orchestrator]
        D[Storage Service]
    end
    
    subgraph "Vault Client"
        VC[Vault Client SDK]
        AM[AppRole Auth]
        LS[Lease Manager]
    end
    
    subgraph "HashiCorp Vault"
        VS[Vault Server]
        AU[Auth Backend]
        SE[Secrets Engine]
        AU2[Audit Device]
    end
    
    subgraph "External Systems"
        PG[(PostgreSQL)]
        NATS[NATS]
        API[External APIs]
    end
    
    A --> VC
    B --> VC
    C --> VC
    D --> VC
    VC --> AM
    VC --> LS
    LS --> VS
    VS --> AU
    VS --> SE
    VS --> AU2
    SE --> PG
    SE --> NATS
    SE --> API
```

### Authentication Strategy

We use **AppRole Authentication** for machine-to-machine authentication:

```mermaid
sequenceDiagram
    participant App as securAIty App
    participant Vault as HashiCorp Vault
    
    App->>Vault: Login with Role ID + Secret ID
    Vault->>Vault: Validate AppRole credentials
    Vault->>App: Return Client Token + Lease Duration
    App->>Vault: Access Secrets with Token
    Vault->>Vault: Validate Token
    Vault->>App: Return Secret Data
    Note over App,Vault: Token auto-renewed before expiry
```

### AppRole Configuration

```bash
# Enable AppRole authentication
vault auth enable approle

# Create AppRole for securAIty
vault write auth/approle/role/securAIty \
    token_policies="securAIty-policy" \
    token_ttl=1h \
    token_max_ttl=4h \
    token_num_uses=0 \
    secret_id_ttl=24h \
    secret_id_num_uses=0 \
    bind_secret_id=true

# Get Role ID
vault read auth/approle/role/securAIty/role-id

# Generate Secret ID
vault write -f auth/approle/role/securAIty/secret-id
```

### Secrets Organization

```
Secret Path Structure:
├── secret/
│   ├── production/
│   │   ├── database/
│   │   │   ├── postgres (credentials)
│   │   │   └── redis (credentials)
│   │   ├── nats/
│   │   │   └── credentials
│   │   ├── jwt/
│   │   │   └── signing-key
│   │   └── encryption/
│   │       └── master-key
│   └── development/
│       └── ...
├── database/
│   ├── creds/
│   │   ├── securAIty-read-only (dynamic)
│   │   └── securAIty-read-write (dynamic)
│   └── static/
│       └── admin-credentials
└── transit/
    └── keys/
        ├── encryption-key
        └── signing-key
```

### Vault Client Implementation

```python
class VaultClient:
    """Async Vault client for secrets management."""
    
    def __init__(self, config: VaultConfig):
        self.config = config
        self._client: Optional[hvac.Client] = None
        self._token: Optional[str] = None
        self._leases: Dict[str, SecretLease] = {}
    
    async def connect(self) -> None:
        """Connect and authenticate with Vault."""
        self._client = hvac.Client(
            url=self.config.url,
            namespace=self.config.namespace,
            verify=self.config.verify,
        )
        
        # AppRole authentication
        response = self._client.auth.approle.login(
            role_id=self.config.approle_role_id,
            secret_id=self.config.approle_secret_id,
        )
        
        self._token = response["auth"]["client_token"]
        self._client.token = self._token
        
        # Schedule token renewal
        await self._schedule_token_renewal(
            response["auth"]["lease_duration"]
        )
    
    async def get_secret(
        self, 
        path: str, 
        mount_point: str = "secret"
    ) -> Dict[str, Any]:
        """Retrieve secret from KV v2 engine."""
        response = self._client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=mount_point,
        )
        return response["data"]["data"]
    
    async def get_dynamic_secret(
        self, 
        path: str,
        mount_point: str = "database"
    ) -> SecretLease:
        """Retrieve dynamic secret with lease."""
        response = self._client.read(path)
        
        lease = SecretLease(
            lease_id=response["lease_id"],
            lease_duration=response["lease_duration"],
            secret_data=response["data"],
        )
        
        self._leases[lease.lease_id] = lease
        return lease
    
    async def renew_lease(self, lease_id: str) -> SecretLease:
        """Renew dynamic secret lease."""
        response = self._client.sys.renew_lease(lease_id=lease_id)
        # Update lease metadata
        ...
    
    async def revoke_lease(self, lease_id: str) -> None:
        """Revoke dynamic secret lease."""
        self._client.sys.revoke_lease(lease_id=lease_id)
        self._leases.pop(lease_id, None)
```

### Dynamic Database Credentials

```python
# Configure PostgreSQL secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/postgresql \
    plugin_name=postgresql-database-plugin \
    allowed_roles="securAIty-read-only,securAIty-read-write" \
    connection_url="postgresql://{{username}}:{{password}}@postgres:5432/security_db?sslmode=disable" \
    username="vault-admin" \
    password="admin-password"

# Create read-only role
vault write database/roles/securAIty-read-only \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# Create read-write role
vault write database/roles/securAIty-read-write \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# Application usage
credentials = await vault.get_dynamic_secret(
    "database/creds/securAIty-read-write"
)
# credentials.secret_data contains:
# {
#   "username": "v-token-securAIty-read-write-abc123",
#   "password": "generated-password"
# }
```

### Transit Engine for Encryption

```python
# Enable transit secrets engine
vault secrets enable transit

# Create encryption key
vault write -f transit/keys/encryption-key \
    type=aes256-gcm96 \
    exportable=true \
    allow_plaintext_backup=false

# Encrypt data
response = vault.write(
    "transit/encrypt/encryption-key",
    plaintext=base64.b64encode(plaintext_data).decode()
)
ciphertext = response["data"]["ciphertext"]

# Decrypt data
response = vault.write(
    "transit/decrypt/encryption-key",
    ciphertext=ciphertext
)
plaintext = base64.b64decode(response["data"]["plaintext"])
```

## Consequences

### Positive

1. **Centralized Secrets**: Single source of truth for all secrets
2. **Audit Trail**: Complete logging of all secret access
3. **Dynamic Credentials**: Automatic credential generation and rotation
4. **Lease Management**: Time-limited access reduces exposure
5. **Fine-Grained Access**: Policy-based access control
6. **Encryption as Service**: Transit engine for application encryption
7. **High Availability**: Vault clustering for production resilience

### Trade-offs

1. **Operational Complexity**: Vault requires dedicated operational expertise
2. **Additional Dependency**: System depends on Vault availability
3. **Learning Curve**: Team needs Vault training
4. **Performance Overhead**: Network calls for secret retrieval

### Negative

1. **Single Point of Failure**: Without HA cluster, Vault outage blocks all operations
2. **Bootstrapping Complexity**: Chicken-egg problem for Vault authentication
3. **Cost**: Vault Enterprise features require licensing

## Security Policies

### AppRole Policy

```hcl
# securAIty-policy.hcl
path "secret/data/production/*" {
  capabilities = ["read", "list"]
}

path "secret/data/development/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "database/creds/*" {
  capabilities = ["read"]
}

path "transit/encrypt/*" {
  capabilities = ["update"]
}

path "transit/decrypt/*" {
  capabilities = ["update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}
```

### Apply Policy

```bash
vault policy write securAIty-policy securAIty-policy.hcl
```

## Deployment Configuration

### Docker Compose (Development)

```yaml
vault:
  image: hashicorp/vault:1.15
  container_name: securAIty-vault
  command: server -config=/etc/vault/vault.hcl
  cap_add:
    - IPC_LOCK
  environment:
    VAULT_DEV_ROOT_TOKEN_ID_FILE: /run/secrets/vault_root_token
    VAULT_ADDR: http://0.0.0.0:8200
  ports:
    - "8200:8200"
  volumes:
    - ./docker/vault/vault.hcl:/etc/vault/vault.hcl:ro
    - vault_data:/vault/data
  networks:
    - securAIty_internal
  healthcheck:
    test: ["CMD", "vault", "status", "-format=json"]
    interval: 10s
    timeout: 5s
    retries: 3
  secrets:
    - vault_root_token
```

### Vault Server Configuration

```hcl
# vault.hcl
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true  # Enable TLS in production
}

storage "file" {
  path = "/vault/data"
}

api_addr = "http://vault:8200"

# Enable UI for development
ui = true

# Audit logging
audit {
  type = "file"
  options = {
    file_path = "/vault/logs/audit.log"
  }
}
```

### Production HA Configuration

```hcl
# vault.hcl (Production)
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file  = "/vault/certs/vault.key"
  tls_min_version = "tls12"
}

storage "consul" {
  address = "consul:8500"
  path    = "vault/"
  scheme  = "http"
}

api_addr = "https://vault.securAIty.local:8200"
cluster_addr = "https://vault:8201"

ui = false

# Telemetry
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
```

## Secret Rotation

### Automatic Rotation

```python
class SecretRotationManager:
    """Manage automatic secret rotation."""
    
    def __init__(self, vault_client: VaultClient):
        self.vault = vault_client
        self._rotation_tasks: Dict[str, asyncio.Task] = {}
    
    async def start_rotation_schedule(
        self,
        secret_path: str,
        rotation_interval: timedelta
    ) -> None:
        """Schedule automatic secret rotation."""
        async def rotate():
            while True:
                await asyncio.sleep(rotation_interval.total_seconds())
                await self._rotate_secret(secret_path)
        
        task = asyncio.create_task(rotate())
        self._rotation_tasks[secret_path] = task
    
    async def _rotate_secret(self, path: str) -> None:
        """Rotate secret at given path."""
        # Generate new secret
        new_secret = generate_secure_secret()
        
        # Write new version
        await self.vault.set_secret(path, {"value": new_secret})
        
        # Notify services to reload
        await self._notify_services(path)
```

### Manual Rotation

```bash
# Generate new database credentials
vault write -force database/rotate-root/postgresql

# Rotate encryption key
vault write -f transit/keys/encryption-key/rotate

# Update static secret
vault kv put secret/production/jwt/signing-key value=$(openssl rand -base64 64)
```

## Monitoring

### Key Metrics

```prometheus
# Vault Server Metrics
vault_core_unsealed
vault_core_active
vault_core_standby

# Secret Operations
vault_secret_count{operation="read"}
vault_secret_count{operation="write"}
vault_secret_count{operation="delete"}

# Authentication
vault_token_count{type="service"}
vault_token_count{type="renewable"}

# Lease Metrics
vault_lease_count{status="active"}
vault_lease_duration_seconds

# Performance
vault_runtime_alloc_bytes
vault_runtime_total_gc_pause_seconds
```

### Health Checks

```python
async def check_vault_health(vault_client: VaultClient) -> HealthStatus:
    """Check Vault health status."""
    try:
        health = vault_client.sys.read_health_status()
        
        if health["initialized"] and not health["sealed"]:
            if health.get("standby"):
                return HealthStatus.DEGRADED  # Standby node
            return HealthStatus.HEALTHY
        elif health["sealed"]:
            return HealthStatus.UNHEALTHY  # Sealed vault
        else:
            return HealthStatus.UNHEALTHY  # Not initialized
    except Exception:
        return HealthStatus.UNHEALTHY
```

## Alternatives Considered

### AWS Secrets Manager

**Pros:**
- Fully managed service
- Automatic rotation for RDS
- Integrated with IAM

**Cons:**
- AWS vendor lock-in
- Higher cost at scale
- Limited to AWS ecosystem
- No dynamic secrets for non-AWS services

**Verdict**: Limits multi-cloud deployment options.

### Azure Key Vault

**Pros:**
- Azure integration
- HSM-backed storage
- Good compliance certifications

**Cons:**
- Azure vendor lock-in
- Complex pricing model
- Limited dynamic secret types

**Verdict**: Limits multi-cloud deployment options.

### Doppler

**Pros:**
- Developer-friendly UI
- Easy setup
- Good team collaboration features

**Cons:**
- SaaS-only (no self-hosted option at time of decision)
- Less mature than Vault
- Limited dynamic secret support

**Verdict**: Insufficient for advanced use cases like dynamic database credentials.

### Environment Variables

**Pros:**
- Simple
- No external dependency

**Cons:**
- No audit trail
- Difficult rotation
- Exposed in process listings
- No access control
- Version control risks

**Verdict**: Insecure and does not meet compliance requirements.

## Compliance Considerations

### Audit Logging

Enable comprehensive audit logging:

```bash
# Enable file audit device
vault audit enable file file_path=/vault/logs/audit.log

# Enable syslog audit device
vault audit enable syslog tag=vault facility=auth
```

### Access Control

All secret access requires authentication and authorization:

```bash
# Verify policy enforcement
vault token lookup -self

# Test policy
vault token create -policy=securAIty-policy
```

### Encryption

All secrets encrypted at rest and in transit:

- At rest: AES-256-GCM encryption
- In transit: TLS 1.3 minimum
- Key rotation: Automatic via transit engine

## References

- [HashiCorp Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [AppRole Authentication](https://developer.hashicorp.com/vault/docs/auth/approle)
- [Dynamic Secrets](https://developer.hashicorp.com/vault/docs/concepts/dynamic-secrets)
- [Transit Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [Vault Best Practices](https://developer.hashicorp.com/vault/tutorials/best-practices)

---

**Last Updated**: March 26, 2026
