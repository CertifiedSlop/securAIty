# Deployment Runbook

**Purpose**: Step-by-step guide for deploying securAIty to production.

**Audience**: DevOps engineers, system administrators

**Last Updated**: 2026-03-26

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Configuration](#environment-configuration)
3. [Docker Secrets Setup](#docker-secrets-setup)
4. [Infrastructure Deployment](#infrastructure-deployment)
5. [Vault Initialization](#vault-initialization)
6. [Database Setup](#database-setup)
7. [Application Deployment](#application-deployment)
8. [Health Verification](#health-verification)
9. [First-Time Configuration](#first-time-configuration)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 50 GB SSD | 100 GB NVMe |
| Network | 1 Gbps | 10 Gbps |

### Software Requirements

```bash
# Verify Docker version (24+)
docker --version
# Expected: Docker version 24.0.0 or higher

# Verify Docker Compose (2.20+)
docker compose version
# Expected: Docker Compose version 2.20.0 or higher

# Verify Python (3.12+)
python3 --version
# Expected: Python 3.12.0 or higher
```

### Required Tools

- Docker 24.0+
- Docker Compose 2.20+
- Git
- Make (optional, for convenience commands)
- Text editor (vim, nano, VS Code)

---

## Environment Configuration

### Step 1: Clone Repository

```bash
git clone https://github.com/your-org/securAIty.git
cd securAIty
```

### Step 2: Create Environment File

```bash
cp .env.example .env
```

### Step 3: Configure Environment Variables

Edit `.env` with your production values:

```bash
# Application
APP_ENV=production
APP_DEBUG=false
APP_LOG_LEVEL=info

# Database
POSTGRES_USER=securAIty
POSTGRES_PASSWORD=<generate-secure-password>
POSTGRES_DB=securAIty
DATABASE_URL=postgresql+asyncpg://securAIty:<password>@postgres:5432/securAIty

# NATS
NATS_URL=nats://nats:4222
NATS_CLUSTER_ID=security-cluster

# Vault
VAULT_URL=http://vault:8200
VAULT_TOKEN=<root-token-from-init>
VAULT_SKIP_VERIFY=false

# JWT
JWT_SECRET_KEY=<generate-256-bit-random-key>
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Security
SECRET_KEY=<generate-32-byte-random-key-for-encryption>
CORS_ORIGINS=https://your-domain.com
RATE_LIMIT_PER_MINUTE=100
```

### Generate Secure Random Values

```bash
# Generate database password (32 chars)
openssl rand -base64 32

# Generate JWT secret (256-bit)
openssl rand -hex 32

# Generate encryption key (32 bytes)
openssl rand -hex 32

# Generate Vault root token
openssl rand -hex 24
```

---

## Docker Secrets Setup

### Step 1: Create Secrets Directory

```bash
mkdir -p secrets/
chmod 700 secrets/
```

### Step 2: Create Secret Files

```bash
# Database password
echo -n "<your-database-password>" > secrets/db_password
chmod 600 secrets/db_password

# Vault root token
echo -n "<your-vault-root-token>" > secrets/vault_token
chmod 600 secrets/vault_token

# JWT signing key
openssl rand -hex 32 > secrets/jwt_key
chmod 600 secrets/jwt_key

# Encryption key
openssl rand -hex 32 > secrets/encryption_key
chmod 600 secrets/encryption_key
```

### Step 3: Verify Secrets

```bash
ls -la secrets/
# Expected: 4 files with 600 permissions
```

---

## Infrastructure Deployment

### Step 1: Start Infrastructure Services

```bash
# Start NATS, PostgreSQL, and Vault
docker compose up -d nats postgres vault
```

### Step 2: Verify Services

```bash
# Check container status
docker compose ps

# Expected output:
# NAME                STATUS          PORTS
# securAIty-nats      Up              0.0.0.0:4222->4222/tcp
# securAIty-postgres  Up              0.0.0.0:5432->5432/tcp
# securAIty-vault     Up              0.0.0.0:8200->8200/tcp
```

### Step 3: Check Service Logs

```bash
# NATS logs
docker compose logs nats | tail -20

# PostgreSQL logs
docker compose logs postgres | tail -20

# Vault logs
docker compose logs vault | tail -20
```

---

## Vault Initialization

### Step 1: Initialize Vault (First Time Only)

```bash
# Get Vault container ID
VAULT_CONTAINER=$(docker compose ps -q vault)

# Initialize Vault
docker exec -it $VAULT_CONTAINER vault operator init \
  --init-shares=5 \
  --init-threshold=3 \
  --format=json > secrets/vault_init.json

chmod 600 secrets/vault_init.json
```

### Step 2: Extract Unseal Keys and Root Token

```bash
# Extract unseal keys (save these securely!)
jq -r '.unseal_keys_b64[]' secrets/vault_init.json

# Extract root token
jq -r '.root_token' secrets/vault_init.json
```

**⚠️ CRITICAL**: Store unseal keys in a secure location (password manager, safe). You need 3 of 5 keys to unseal Vault.

### Step 3: Unseal Vault

```bash
# Unseal with 3 keys
docker exec -it $VAULT_CONTAINER vault operator unseal <key1>
docker exec -it $VAULT_CONTAINER vault operator unseal <key2>
docker exec -it $VAULT_CONTAINER vault operator unseal <key3>

# Verify unseal status
docker exec -it $VAULT_CONTAINER vault status
# Expected: Sealed = false
```

### Step 4: Enable Secrets Engines

```bash
# Set root token
export VAULT_TOKEN="<root-token>"
export VAULT_ADDR="http://localhost:8200"

# Enable KV v2 for application secrets
vault secrets enable -path=secret kv-v2

# Enable database secrets engine
vault secrets enable database

# Configure database credentials
vault write database/config/securAIty \
  plugin_name=postgresql \
  allowed_roles="securAIty-role" \
  connection_url="postgresql://{{username}}:{{password}}@postgres:5432/securAIty?sslmode=disable" \
  username="postgres" \
  password="<postgres-password>"

# Create database role
vault write database/roles/securAIty-role \
  db_name=securAIty \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"
```

---

## Database Setup

### Step 1: Run Migrations

```bash
# Wait for PostgreSQL to be ready
sleep 10

# Run database migrations
docker compose run --rm app python -m src.securAIty.storage.migrate
```

### Step 2: Verify Database Schema

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U securAIty -d securAIty -c "\dt"

# Expected tables:
# - events
# - incidents
# - agents
# - users
# - audit_logs
```

---

## Application Deployment

### Step 1: Build Application Image

```bash
# Build production image
docker compose build app
```

### Step 2: Start Application

```bash
# Start securAIty application
docker compose up -d app

# Check status
docker compose ps app
```

### Step 3: Verify Application Logs

```bash
# Stream application logs
docker compose logs -f app
```

Expected log messages:
```
INFO: Application startup complete
INFO: Connected to NATS at nats://nats:4222
INFO: Connected to PostgreSQL at postgres:5432
INFO: Connected to Vault at http://vault:8200
INFO: All 5 agents registered and healthy
```

---

## Health Verification

### Step 1: Check Health Endpoints

```bash
# Liveness probe
curl http://localhost:8000/api/v1/health/live
# Expected: {"status": "healthy"}

# Readiness probe
curl http://localhost:8000/api/v1/health/ready
# Expected: {"status": "ready", "checks": {...}}

# Complete health check
curl http://localhost:8000/api/v1/health/complete
# Expected: All subsystems healthy
```

### Step 2: Verify Agent Status

```bash
curl http://localhost:8000/api/v1/agents
# Expected: 5 agents with status "online"
```

### Step 3: Test Authentication

```bash
# Login with default admin
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "<admin-password>"}'

# Expected: {"access_token": "...", "refresh_token": "..."}
```

---

## First-Time Configuration

### Step 1: Change Default Admin Password

```bash
# Login with default credentials
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | jq -r '.access_token')

# Change password
curl -X POST http://localhost:8000/api/v1/auth/change-password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"old_password": "admin123", "new_password": "<your-secure-password>"}'
```

### Step 2: Configure Security Policies

```bash
# Create default security policy
curl -X POST http://localhost:8000/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "default-security-policy",
    "description": "Default security policy for all environments",
    "rules": [...]
  }'
```

### Step 3: Configure Agent Settings

See [Agent Configuration](../agents/overview.md#configuration) for detailed setup.

---

## Troubleshooting

### Issue: Containers Won't Start

```bash
# Check Docker logs
docker compose logs

# Check resource availability
docker stats --no-stream

# Verify network
docker network ls
docker network inspect securAIty_default
```

### Issue: Vault Sealed After Restart

```bash
# Unseal Vault (need 3 of 5 keys)
docker compose exec vault vault operator unseal <key1>
docker compose exec vault vault operator unseal <key2>
docker compose exec vault vault operator unseal <key3>

# Verify
docker compose exec vault vault status
```

### Issue: Database Connection Failed

```bash
# Check PostgreSQL status
docker compose exec postgres pg_isready

# Check connection string
docker compose exec app env | grep DATABASE_URL

# Test connection
docker compose exec app python -c "from src.securAIty.storage import get_db; print('OK')"
```

### Issue: NATS Connection Failed

```bash
# Check NATS status
curl http://localhost:8222/varz

# Check event bus connection
docker compose exec app python -c "from src.securAIty.events import EventBus; print('OK')"
```

### Issue: Application Crashes on Startup

```bash
# Check application logs
docker compose logs app | tail -50

# Verify environment variables
docker compose exec app env | sort

# Check secret files
docker compose exec app ls -la /run/secrets/
```

---

## Rollback Procedures

### Rollback to Previous Version

```bash
# Stop current application
docker compose stop app

# Tag current image as backup
docker tag securAIty-app:latest securAIty-app:backup-$(date +%Y%m%d)

# Pull previous version
docker pull securAIty-app:<previous-tag>

# Start previous version
docker compose up -d app

# Verify rollback
curl http://localhost:8000/api/v1/health/live
```

### Database Rollback

```bash
# Restore from backup
pg_restore -h localhost -U securAIty -d securAIty < backup.sql

# Or restore from specific backup file
docker compose exec postgres pg_restore -U securAIty -d securAIty /backups/backup-20260326.dump
```

---

## Post-Deployment Checklist

- [ ] All containers running (`docker compose ps`)
- [ ] Health endpoints responding
- [ ] All 5 agents online
- [ ] Vault unsealed and accessible
- [ ] Database migrations complete
- [ ] Admin password changed
- [ ] Secrets stored securely
- [ ] Backup procedures configured
- [ ] Monitoring enabled
- [ ] Logs aggregating

---

## Next Steps

1. [Configure Monitoring](monitoring.md)
2. [Set Up Backups](backup-recovery.md)
3. [Review Security Hardening](security-hardening.md)
4. [Configure Incident Response](incident-response.md)

---

**Document Version**: 1.0  
**Maintained By**: securAIty DevOps Team
