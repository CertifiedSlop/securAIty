# Backup and Recovery Runbook

**Purpose**: Procedures for backing up and recovering securAIty platform components.

**Audience**: DevOps engineers, system administrators, DR team

**Last Updated**: 2026-03-26

---

## Table of Contents

1. [Backup Overview](#backup-overview)
2. [Database Backup](#database-backup)
3. [Vault Backup](#vault-backup)
4. [NATS Backup](#nats-backup)
5. [Configuration Backup](#configuration-backup)
6. [Recovery Procedures](#recovery-procedures)
7. [Disaster Recovery Testing](#disaster-recovery-testing)

---

## Backup Overview

### Backup Summary

| Component | Backup Method | Frequency | Retention | RPO | RTO |
|-----------|--------------|-----------|-----------|-----|-----|
| PostgreSQL | pg_dump + WAL archiving | Continuous + Daily | 30 days | 1 hour | 4 hours |
| Vault | Raft snapshots | Hourly + Daily | 7 days | 1 hour | 2 hours |
| NATS JetStream | File backup | Daily | 7 days | 24 hours | 2 hours |
| Configuration | Git + File backup | On change + Daily | 90 days | N/A | 1 hour |
| Secrets | Vault (primary) | N/A | N/A | N/A | N/A |

### Backup Storage

```yaml
backup_locations:
  primary:
    path: /backups
    type: Local SSD
    retention: 7 days
    
  secondary:
    path: s3://securAIty-backups/
    type: Object Storage
    retention: 30 days
    encryption: AES-256
    
  archive:
    path: s3://securAIty-archive/
    type: Glacier
    retention: 365 days
    encryption: AES-256
```

### Backup Schedule

```bash
# Crontab for backup jobs
# Database backups
0 2 * * * /scripts/backup_db.sh
0 * * * * /scripts/backup_db_incremental.sh

# Vault snapshots
0 * * * * /scripts/backup_vault.sh
0 3 * * * /scripts/backup_vault_full.sh

# NATS backup
0 3 * * * /scripts/backup_nats.sh

# Configuration backup
0 4 * * * /scripts/backup_config.sh

# Upload to S3
0 5 * * * /scripts/sync_backups_s3.sh
```

---

## Database Backup

### Full Backup Script

```bash
#!/bin/bash
# backup_db.sh - Full PostgreSQL backup

set -euo pipefail

BACKUP_DIR="/backups/postgres"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/securAIty_${DATE}.sql.gz"
LOG_FILE="/var/log/backups/db_backup.log"

log() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG_FILE"
}

log "Starting PostgreSQL backup"

# Create backup directory if not exists
mkdir -p "$BACKUP_DIR"

# Perform backup
docker compose exec -T postgres pg_dump \
    -U securAIty \
    -d securAIty \
    -F c \
    -Z 9 \
    -f "/tmp/securAIty_${DATE}.dump"

# Copy to backup directory
docker compose exec -T postgres cat "/tmp/securAIty_${DATE}.dump" > "$BACKUP_FILE"

# Verify backup
if gzip -t "$BACKUP_FILE" 2>/dev/null; then
    log "Backup completed successfully: $BACKUP_FILE"
    
    # Upload to S3
    aws s3 cp "$BACKUP_FILE" "s3://securAIty-backups/postgres/" \
        --sse AES256
    
    log "Backup uploaded to S3"
else
    log "ERROR: Backup verification failed"
    exit 1
fi

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete
log "Old backups cleaned up"
```

### WAL Archiving Configuration

```postgresql
# postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'wal-g wal-push %p'
archive_timeout = 300

# wal-g configuration
# /etc/wal-g/config.json
{
    "AWS_ACCESS_KEY_ID": "<key>",
    "AWS_SECRET_ACCESS_KEY": "<secret>",
    "WALG_S3_PREFIX": "s3://securAIty-backups/wal",
    "WALG_COMPRESSION_METHOD": "lz4"
}
```

### Point-in-Time Recovery

```bash
#!/bin/bash
# restore_db_pitr.sh - Point-in-time recovery

set -euo pipefail

TARGET_TIME="$1"  # Format: '2026-03-26 14:30:00'
RESTORE_DIR="/restore/postgres"

log "Starting PITR to $TARGET_TIME"

# Download base backup
BACKUP=$(aws s3 ls s3://securAIty-backups/postgres/ \
    | sort | grep ".sql.gz" | awk '{print $4}' | tail -1)

aws s3 cp "s3://securAIty-backups/postgres/$BACKUP" "$RESTORE_DIR/"

# Restore
docker compose stop app
docker compose run --rm postgres pg_restore \
    -U securAIty \
    -d securAIty \
    "$RESTORE_DIR/$BACKUP"

# Apply WAL logs up to target time
wal-g backup-fetch "$RESTORE_DIR/base" LATEST
wal-g wal-push --restore-until="$TARGET_TIME"

log "PITR completed"
```

---

## Vault Backup

### Raft Snapshot Backup

```bash
#!/bin/bash
# backup_vault.sh - Vault Raft snapshot

set -euo pipefail

BACKUP_DIR="/backups/vault"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/vault_raft_${DATE}.snap"
LOG_FILE="/var/log/backups/vault_backup.log"

log() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG_FILE"
}

log "Starting Vault Raft snapshot"

mkdir -p "$BACKUP_DIR"

# Get Vault token from secrets
export VAULT_TOKEN=$(cat /run/secrets/vault_token)
export VAULT_ADDR="http://vault:8200"

# Create snapshot
docker compose exec vault vault operator raft snapshot save "/tmp/vault_${DATE}.snap"

# Copy snapshot
docker compose exec vault cat "/tmp/vault_${DATE}.snap" > "$BACKUP_FILE"

# Verify snapshot
if docker compose exec vault vault operator raft snapshot inspect "$BACKUP_FILE"; then
    log "Snapshot verified: $BACKUP_FILE"
    
    # Upload to S3
    aws s3 cp "$BACKUP_FILE" "s3://securAIty-backups/vault/" \
        --sse AES256
    
    log "Snapshot uploaded to S3"
else
    log "ERROR: Snapshot verification failed"
    exit 1
fi

# Cleanup old snapshots
find "$BACKUP_DIR" -name "*.snap" -mtime +7 -delete
log "Old snapshots cleaned up"
```

### Auto-Unseal Configuration

```hcl
# vault.hcl - Auto-unseal with cloud KMS

storage "raft" {
  path = "/vault/data"
  
  retry_join {
    leader_api_addr = "http://vault-1:8200"
  }
  retry_join {
    leader_api_addr = "http://vault-2:8200"
  }
  retry_join {
    leader_api_addr = "http://vault-3:8200"
  }
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal"
}

# Or with Azure Key Vault
# seal "azurekeyvault" {
#   vault_name      = "my-vault"
#   key_name        = "vault-unseal-key"
# }

# Or with Google Cloud KMS
# seal "gcpckms" {
#   project    = "my-project"
#   region     = "us-central1"
#   key_ring   = "vault-keyring"
#   crypto_key = "vault-unseal"
# }
```

### Vault Recovery

```bash
#!/bin/bash
# restore_vault.sh - Restore Vault from snapshot

set -euo pipefail

SNAPSHOT_FILE="$1"

log "Starting Vault restoration from $SNAPSHOT_FILE"

# Stop Vault
docker compose stop vault

# Initialize fresh Vault (if needed)
docker compose run --rm vault vault operator init -key-shares=5 -key-threshold=3

# Unseal Vault (need 3 keys)
docker compose exec vault vault operator unseal <key1>
docker compose exec vault vault operator unseal <key2>
docker compose exec vault vault operator unseal <key3>

# Restore snapshot
export VAULT_TOKEN="<root-token>"
docker compose exec vault vault operator raft snapshot restore "$SNAPSHOT_FILE" -force

# Restart Vault
docker compose start vault

# Verify
docker compose exec vault vault status
log "Vault restoration completed"
```

---

## NATS Backup

### JetStream File Backup

```bash
#!/bin/bash
# backup_nats.sh - NATS JetStream backup

set -euo pipefail

BACKUP_DIR="/backups/nats"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/nats_jetstream_${DATE}.tar.gz"
LOG_FILE="/var/log/backups/nats_backup.log"

log() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG_FILE"
}

log "Starting NATS JetStream backup"

mkdir -p "$BACKUP_DIR"

# Stop NATS briefly for consistent backup
docker compose stop nats

# Backup JetStream storage directory
tar -czf "$BACKUP_FILE" \
    -C /var/lib/docker/volumes/securAIty_nats_data/_data \
    jetstream

# Restart NATS
docker compose start nats

# Verify backup
if tar -tzf "$BACKUP_FILE" > /dev/null; then
    log "Backup verified: $BACKUP_FILE"
    
    # Upload to S3
    aws s3 cp "$BACKUP_FILE" "s3://securAIty-backups/nats/" \
        --sse AES256
    
    log "Backup uploaded to S3"
else
    log "ERROR: Backup verification failed"
    exit 1
fi

# Cleanup old backups
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete
log "Old backups cleaned up"
```

### NATS Stream Backup (Live)

```bash
#!/bin/bash
# backup_nats_stream.sh - Live stream backup using nats CLI

set -euo pipefail

BACKUP_DIR="/backups/nats/streams"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup SECURITY_EVENTS stream
nats stream backup SECURITY_EVENTS \
    --server=nats://localhost:4222 \
    "$BACKUP_DIR/SECURITY_EVENTS_${DATE}"

# Backup other streams
nats stream backup AUDIT_LOGS \
    --server=nats://localhost:4222 \
    "$BACKUP_DIR/AUDIT_LOGS_${DATE}"

echo "Stream backup completed"
```

---

## Configuration Backup

### Configuration Backup Script

```bash
#!/bin/bash
# backup_config.sh - Backup all configuration files

set -euo pipefail

BACKUP_DIR="/backups/config"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/config_${DATE}.tar.gz"

log() {
    echo "[$(date -Iseconds)] $1"
}

log "Starting configuration backup"

mkdir -p "$BACKUP_DIR"

# Create backup archive
tar -czf "$BACKUP_FILE" \
    /home/quizz/Documents/securAIty/.env \
    /home/quizz/Documents/securAIty/docker-compose.yml \
    /home/quizz/Documents/securAIty/docker-compose.prod.yml \
    /home/quizz/Documents/securAIty/docker/ \
    /home/quizz/Documents/securAIty/config/ \
    /home/quizz/Documents/securAIty/secrets/

log "Configuration backup: $BACKUP_FILE"

# Git backup
cd /home/quizz/Documents/securAIty
git add -A
git commit -m "Automated config backup $(date -I)" || true
git push origin main

log "Git backup completed"

# Upload to S3
aws s3 cp "$BACKUP_FILE" "s3://securAIty-backups/config/" \
    --sse AES256

log "Configuration backup completed"
```

### Git Configuration Backup

```bash
#!/bin/bash
# setup_git_backup.sh - Configure automatic git backups

# Create backup branch
git checkout -b backups

# Add pre-commit hook for automatic backups
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Auto-backup on commit

BACKUP_DATE=$(date +%Y%m%d)
git archive --format=tar --prefix=securAIty/ HEAD | gzip > "../backups/securAIty_${BACKUP_DATE}.tar.gz"
echo "Backup created: securAIty_${BACKUP_DATE}.tar.gz"
EOF

chmod +x .git/hooks/pre-commit
```

---

## Recovery Procedures

### Full System Recovery

```bash
#!/bin/bash
# recover_full.sh - Full system recovery

set -euo pipefail

log() {
    echo "[$(date -Iseconds)] $1"
}

log "=== Starting Full System Recovery ==="

# Step 1: Restore infrastructure
log "Step 1: Starting infrastructure..."
docker compose up -d postgres vault nats

# Step 2: Wait for services
log "Waiting for PostgreSQL..."
until docker compose exec postgres pg_isready; do
    sleep 2
done

log "Waiting for Vault..."
until docker compose exec vault vault status 2>/dev/null; do
    sleep 2
done

# Step 3: Restore Vault
log "Step 3: Restoring Vault..."
./restore_vault.sh /backups/vault/latest.snap

# Step 4: Restore Database
log "Step 4: Restoring Database..."
./restore_db.sh /backups/postgres/latest.dump

# Step 5: Restore NATS
log "Step 5: Restoring NATS..."
./restore_nats.sh /backups/nats/latest.tar.gz

# Step 6: Start application
log "Step 6: Starting application..."
docker compose up -d app

# Step 7: Verify
log "Step 7: Verifying recovery..."
sleep 30
curl -f http://localhost:8000/api/v1/health/complete

log "=== Full System Recovery Complete ==="
```

### Database Recovery

```bash
#!/bin/bash
# restore_db.sh - Restore database from backup

set -euo pipefail

BACKUP_FILE="$1"

log "Starting database restore from $BACKUP_FILE"

# Stop application
docker compose stop app

# Drop and recreate database
docker compose exec postgres psql -U securAIty -c "DROP DATABASE IF EXISTS securAIty;"
docker compose exec postgres psql -U securAIty -c "CREATE DATABASE securAIty;"

# Restore
docker compose exec -T postgres pg_restore \
    -U securAIty \
    -d securAIty \
    < "$BACKUP_FILE"

# Run migrations
docker compose run --rm app python -m src.securAIty.storage.migrate

# Start application
docker compose start app

log "Database restore completed"
```

### Application Recovery

```bash
#!/bin/bash
# recover_app.sh - Recover application container

set -euo pipefail

log "Starting application recovery"

# Stop current application
docker compose stop app

# Remove old container
docker compose rm -f app

# Pull latest image
docker compose pull app

# Start fresh
docker compose up -d app

# Verify
sleep 10
curl -f http://localhost:8000/api/v1/health/live

log "Application recovery completed"
```

---

## Disaster Recovery Testing

### DR Test Plan

```yaml
dr_test_schedule:
  monthly:
    - Database restore test
    - Configuration restore test
    
  quarterly:
    - Full system recovery test
    - Vault restore test
    - Failover test
    
  annually:
    - Complete DR exercise
    - RTO/RPO validation
    - Team training exercise
```

### DR Test Checklist

```markdown
# DR Test Checklist

## Pre-Test Preparation
- [ ] Schedule maintenance window
- [ ] Notify stakeholders
- [ ] Verify backup availability
- [ ] Prepare test environment
- [ ] Document current state

## Test Execution
- [ ] Simulate failure scenario
- [ ] Execute recovery procedures
- [ ] Document recovery time
- [ ] Verify data integrity
- [ ] Test application functionality

## Post-Test Activities
- [ ] Restore production state
- [ ] Document lessons learned
- [ ] Update runbooks
- [ ] Calculate actual RTO/RPO
- [ ] Report to management
```

### DR Test Report Template

```markdown
# Disaster Recovery Test Report

**Test Date**: YYYY-MM-DD  
**Test Type**: {Full/Partial}  
**Scenario**: {Description of failure scenario}

## Results Summary

| Metric | Target | Actual | Pass/Fail |
|--------|--------|--------|-----------|
| RTO (Database) | 4 hours | X hours | Pass |
| RTO (Vault) | 2 hours | X hours | Pass |
| RTO (Application) | 1 hour | X hours | Pass |
| RPO (Database) | 1 hour | X minutes | Pass |
| RPO (Vault) | 1 hour | X minutes | Pass |

## Issues Encountered

| Issue | Severity | Resolution |
|-------|----------|------------|
| {Issue 1} | High | {Resolution} |

## Action Items

| Action | Owner | Due Date |
|--------|-------|----------|
| {Action 1} | {Name} | {Date} |

## Conclusion

{Summary of test results and recommendations}
```

---

## Related Documents

- [Deployment Runbook](deployment.md)
- [Monitoring Runbook](monitoring.md)
- [Incident Response](incident-response.md)
- [Security Hardening](security-hardening.md)

---

**Document Version**: 1.0  
**Maintained By**: securAIty DevOps Team  
**Review Cycle**: Quarterly  
**Next Review**: 2026-06-26
