# Security Hardening Runbook

**Author:** CertifiedSlop

**Purpose**: Security hardening checklist and procedures for securAIty platform.

**Audience**: Security engineers, DevOps team, compliance officers

**Last Updated**: 2026-03-26

---

## Table of Contents

1. [Container Security](#container-security)
2. [Network Segmentation](#network-segmentation)
3. [TLS Configuration](#tls-configuration)
4. [Secrets Rotation](#secrets-rotation)
5. [Audit Logging](#audit-logging)
6. [Compliance Mapping](#compliance-mapping)

---

## Container Security

### Docker Security Checklist

```yaml
Container_Hardening:
  - Use minimal base images (python:3.12-slim)
  - Run as non-root user
  - Read-only root filesystem
  - Drop all capabilities
  - Add only required capabilities
  - No privileged containers
  - Resource limits configured
  - Health checks enabled
  - No sensitive data in environment variables
  - Use Docker secrets for sensitive data
```

### Production Dockerfile Security

```dockerfile
# Multi-stage build for minimal attack surface
FROM python:3.12-slim as builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.12-slim

# Create non-root user
RUN groupadd --gid 1000 securAIty && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home securAIty

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy from builder
COPY --from=builder /root/.local /home/securAIty/.local
COPY --chown=securAIty:securAIty src/ src/

# Switch to non-root user
USER securAIty

# Read-only filesystem with tmpfs for writable directories
# Configured in docker-compose.yml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health/live')"

CMD ["python", "-m", "uvicorn", "src.securAIty.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose Security

```yaml
services:
  app:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      - /run/secrets:noexec,nosuid,size=10m
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    user: "1000:1000"
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
    networks:
      - internal
    # No exposed ports - behind reverse proxy
```

### CIS Docker Benchmark Mapping

| CIS Control | Implementation | Status |
|-------------|----------------|--------|
| 4.1 | Non-root user | ✅ |
| 4.5 | Content trust enabled | ✅ |
| 4.6 | Health check configured | ✅ |
| 4.7 | Resource limits set | ✅ |
| 4.9 | Read-only filesystem | ✅ |
| 4.10 | No new privileges | ✅ |
| 5.2 | Network segmentation | ✅ |
| 5.25 | No privileged containers | ✅ |

---

## Network Segmentation

### Network Architecture

```mermaid
graph TB
    subgraph "DMZ"
        LB[Load Balancer]
        RP[Reverse Proxy]
    end
    
    subgraph "Application Tier"
        APP[securAIty App]
        API[API Gateway]
    end
    
    subgraph "Data Tier"
        DB[(PostgreSQL)]
        NATS[NATS]
        VAULT[Vault]
    end
    
    subgraph "Management"
        MON[Monitoring]
        LOG[Logging]
    end
    
    LB --> RP
    RP --> API
    API --> APP
    APP --> DB
    APP --> NATS
    APP --> VAULT
    APP --> MON
    APP --> LOG
    
    style DMZ fill:#f9f,stroke:#333
    style "Application Tier" fill:#bbf,stroke:#333
    style "Data Tier" fill:#bfb,stroke:#333
```

### Network Policies

```yaml
# Kubernetes NetworkPolicy example
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: securAIty-app
  namespace: security
spec:
  podSelector:
    matchLabels:
      app: securAIty
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: reverse-proxy
      ports:
        - protocol: TCP
          port: 8000
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - podSelector:
            matchLabels:
              app: nats
      ports:
        - protocol: TCP
          port: 4222
    - to:
        - podSelector:
            matchLabels:
              app: vault
      ports:
        - protocol: TCP
          port: 8200
```

### Firewall Rules

```bash
# iptables rules for host-level security

# Default deny
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (rate limited)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow reverse proxy
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow internal network
iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED: "
```

---

## TLS Configuration

### TLS Best Practices

```yaml
TLS_Settings:
  minimum_version: TLS 1.3
  preferred_version: TLS 1.3
  cipher_suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
    - TLS_AES_128_GCM_SHA256
  key_exchange:
    - X25519
    - secp384r1
  certificate:
    key_size: 4096  # RSA
    signature_algorithm: SHA-256
    validity_days: 365
    auto_renewal: true
```

### Nginx Reverse Proxy TLS

```nginx
server {
    listen 443 ssl http2;
    server_name securAIty.example.com;

    # TLS configuration
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256';
    ssl_ecdh_curve X25519:secp384r1;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Certificate paths
    ssl_certificate /etc/ssl/certs/securAIty.crt;
    ssl_certificate_key /etc/ssl/private/securAIty.key;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/ssl/certs/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    add_header Content-Security-Policy "default-src 'self'";

    location / {
        proxy_pass http://app:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name securAIty.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Certificate Management

```bash
#!/bin/bash
# renew_certs.sh - Automatic certificate renewal

set -euo pipefail

# Using Let's Encrypt with certbot
certbot renew --quiet --post-hook "systemctl reload nginx"

# Verify renewal
echo | openssl s_client -connect securAIty.example.com:443 2>/dev/null | openssl x509 -noout -dates

# Alert if expiring soon
EXPIRY=$(echo | openssl s_client -connect securAIty.example.com:443 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

if [ $DAYS_LEFT -lt 30 ]; then
    echo "WARNING: Certificate expires in $DAYS_LEFT days" | mail -s "Certificate Expiry Warning" security-team@example.com
fi
```

---

## Secrets Rotation

### Rotation Schedule

| Secret Type | Rotation Frequency | Method | Owner |
|-------------|-------------------|--------|-------|
| Database Password | 90 days | Automated (Vault) | DevOps |
| JWT Signing Key | 180 days | Manual | Security |
| Vault Root Token | 30 days | Manual | Security |
| TLS Certificate | 90 days | Automated (certbot) | DevOps |
| API Keys | 90 days | Automated | Security |
| Encryption Keys | 365 days | Manual | Security |

### Database Password Rotation

```bash
#!/bin/bash
# rotate_db_password.sh - Rotate database password

set -euo pipefail

log() {
    echo "[$(date -Iseconds)] $1"
}

log "Starting database password rotation"

# Generate new password
NEW_PASSWORD=$(openssl rand -base64 32)

# Store in Vault
export VAULT_TOKEN=$(cat /run/secrets/vault_token)
vault kv put secret/database/securAIty \
    username=securAIty \
    password="$NEW_PASSWORD"

# Update database
docker compose exec postgres psql -U postgres -c \
    "ALTER USER securAIty WITH PASSWORD '$NEW_PASSWORD';"

# Update connection string in Vault
vault kv put secret/app/config \
    database_url="postgresql+asyncpg://securAIty:${NEW_PASSWORD}@postgres:5432/securAIty"

# Restart application to pick up new credentials
docker compose restart app

# Verify
sleep 10
curl -f http://localhost:8000/api/v1/health/complete

log "Password rotation completed"

# Store old password for rollback (encrypted)
echo "$OLD_PASSWORD" | age -r security-team@example.com > /backups/secrets/db_password_$(date +%Y%m%d).age
```

### JWT Key Rotation

```bash
#!/bin/bash
# rotate_jwt_keys.sh - Rotate JWT signing keys

set -euo pipefail

log() {
    echo "[$(date -Iseconds)] $1"
}

log "Starting JWT key rotation"

# Generate new RSA keypair
openssl genrsa -out jwt_private_new.pem 4096
openssl rsa -in jwt_private_new.pem -pubout -out jwt_public_new.pem

# Store in Vault
export VAULT_TOKEN=$(cat /run/secrets/vault_token)
vault kv put secret/jwt/keys \
    private_key=@jwt_private_new.pem \
    public_key=@jwt_public_new.pem \
    valid_from=$(date -Iseconds)

# Update application (rolling restart)
docker compose restart app

# Verify
sleep 10
curl -f http://localhost:8000/api/v1/health/complete

# Archive old keys
vault kv put secret/jwt/keys_archive/$(date +%Y%m%d) \
    private_key=@jwt_private_old.pem \
    public_key=@jwt_public_old.pem \
    archived_at=$(date -Iseconds)

# Cleanup
rm -f jwt_private_new.pem jwt_public_new.pem

log "JWT key rotation completed"
```

### Vault Token Rotation

```bash
#!/bin/bash
# rotate_vault_token.sh - Rotate Vault root token

set -euo pipefail

log() {
    echo "[$(date -Iseconds)] $1"
}

log "Starting Vault root token rotation"

export VAULT_TOKEN="$OLD_ROOT_TOKEN"
export VAULT_ADDR="http://vault:8200"

# Generate new root token
NEW_TOKEN=$(vault token create -policy=root -ttl=720h -format=json | jq -r '.auth.client_token')

# Update stored token
echo "$NEW_TOKEN" | docker secret create vault_token_new -
docker secret rm vault_token
docker secret create vault_token /run/secrets/vault_token_new

# Update all services
docker compose restart

# Revoke old token
vault token revoke "$OLD_ROOT_TOKEN"

log "Vault token rotation completed"
```

---

## Audit Logging

### Audit Log Configuration

```python
# logging_config.py
import logging
from pythonjsonlogger import jsonlogger

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": jsonlogger.JsonFormatter,
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s %(correlation_id)s %(user_id)s",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stdout",
        },
        "audit": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "json",
            "filename": "/var/log/securAIty/audit.log",
            "maxBytes": 104857600,  # 100MB
            "backupCount": 10,
        },
    },
    "loggers": {
        "securAIty.audit": {
            "level": "INFO",
            "handlers": ["audit", "console"],
            "propagate": False,
        },
    },
}
```

### Audit Events

```python
# Audit event types to log
AUDIT_EVENTS = {
    "authentication": [
        "login_success",
        "login_failure",
        "logout",
        "token_refresh",
        "password_change",
    ],
    "authorization": [
        "access_granted",
        "access_denied",
        "privilege_escalation_attempt",
    ],
    "data_access": [
        "record_viewed",
        "record_created",
        "record_modified",
        "record_deleted",
    ],
    "security": [
        "incident_created",
        "incident_updated",
        "alert_triggered",
        "policy_violation",
    ],
    "administration": [
        "user_created",
        "user_modified",
        "user_deleted",
        "config_changed",
    ],
}
```

### Log Aggregation Setup

```yaml
# Filebeat configuration
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/securAIty/*.log
    fields:
      application: securAIty
    json.keys_under_root: true

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

output.logstash:
  hosts: ["logstash:5044"]

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
```

---

## Compliance Mapping

### SOC 2 Type II Controls

| Control | Implementation | Evidence |
|---------|----------------|----------|
| CC6.1 | Logical access controls | Auth logs, RBAC config |
| CC6.2 | Authentication mechanisms | JWT config, MFA setup |
| CC6.3 | Authorization controls | Policy engine config |
| CC6.6 | Encryption at rest | Vault config, DB encryption |
| CC6.7 | Encryption in transit | TLS config, cipher suites |
| CC7.1 | Intrusion detection | Agent alerts, NATS events |
| CC7.2 | Incident response | Incident runbook, alerts |
| CC8.1 | Change management | Git history, deployment logs |

### ISO 27001 Controls

| Control | Implementation | Status |
|---------|----------------|--------|
| A.9.2.1 | User registration | ✅ |
| A.9.2.4 | Password management | ✅ |
| A.9.4.1 | Information access restriction | ✅ |
| A.10.1.1 | Cryptographic controls | ✅ |
| A.12.4.1 | Event logging | ✅ |
| A.12.4.2 | Protection of log information | ✅ |
| A.12.6.1 | Technical vulnerability management | ✅ |
| A.13.1.1 | Network controls | ✅ |

### NIST CSF Mapping

| Function | Category | Implementation |
|----------|----------|----------------|
| Identify | Asset Management | Agent inventory, CMDB integration |
| Protect | Access Control | JWT auth, RBAC, Vault secrets |
| Protect | Data Security | Encryption, backup, TLS |
| Detect | Continuous Monitoring | Agent detection, NATS events |
| Respond | Response Planning | Incident runbook, escalation |
| Recover | Recovery Planning | Backup/recovery runbook |

---

## Related Documents

- [Deployment Runbook](deployment.md)
- [Incident Response](incident-response.md)
- [Backup & Recovery](backup-recovery.md)
- [Monitoring Runbook](monitoring.md)

---

**Document Version**: 1.0  
**Maintained By**: securAIty Security Team  
**Review Cycle**: Quarterly  
**Next Review**: 2026-06-26

---

&copy; 2026 CertifiedSlop. All rights reserved.
