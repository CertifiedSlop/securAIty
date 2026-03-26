# Docker Infrastructure for securAIty

## Overview

This directory contains Docker configurations for the securAIty security automation platform.

## Components

### NATS Streaming (natss)
- **Purpose**: Message streaming and event-driven architecture
- **Configuration**: `docker/natss/nats.conf`
- **Ports**: 4222 (client), 8222 (monitoring), 6222 (cluster)
- **Persistence**: JetStream with file storage

### PostgreSQL
- **Purpose**: Primary data storage
- **Version**: PostgreSQL 16 Alpine
- **Port**: 5432
- **Initialization**: `docker/postgres/init.sql`

### HashiCorp Vault
- **Purpose**: Secrets management
- **Version**: Vault 1.15
- **Port**: 8200
- **Configuration**: `docker/vault/vault.hcl`

### Application
- **Base**: Python 3.12 slim
- **Multi-stage build**: Yes
- **Non-root user**: Yes (UID 1000)
- **Health check**: HTTP endpoint `/health`

## Quick Start

### Development

```bash
# Generate secrets
make secrets-generate

# Start all services
make docker-run

# View logs
make docker-logs

# Run tests in container
make docker-test

# Open shell in app container
make docker-shell
```

### Production

```bash
# Build production images
make docker-build-prod

# Start with production configuration
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Check health
make docker-health
```

## Security Features

### Container Hardening
- Non-root users (UID 1000 for app, UID 999 for postgres)
- Read-only root filesystems
- `no-new-privileges` security option
- Minimal base images (Alpine, slim)
- Resource limits (CPU, memory)

### Secrets Management
- Docker secrets for sensitive data
- Files in `./secrets/` directory (gitignored)
- Vault integration for runtime secrets

### Network Isolation
- Internal bridge network (172.28.0.0/16)
- Services only expose required ports
- No default inter-container communication

## Directory Structure

```
docker/
├── app/
│   ├── Dockerfile          # Production multi-stage build
│   └── Dockerfile.dev      # Development with hot reload
├── natss/
│   └── nats.conf           # NATS JetStream configuration
├── vault/
│   └── vault.hcl           # Vault server configuration
└── postgres/
    └── init.sql            # Database initialization

```

## Configuration Files

### NATS Configuration
- JetStream enabled with 1GB file store
- Security account with user authentication
- System account for monitoring
- WebSocket support on port 8080

### Vault Configuration
- File backend for persistence
- HTTP listener (TLS disabled for dev)
- 1h default lease TTL
- Prometheus telemetry enabled

### PostgreSQL Initialization
- uuid-ossp and pgcrypto extensions
- Security schema with proper permissions
- Audit log and secrets metadata tables

## Makefile Targets

| Target | Description |
|--------|-------------|
| `docker-build` | Build Docker images |
| `docker-run` | Build and start containers |
| `docker-run-fresh` | Fresh start with volume removal |
| `docker-test` | Run tests in container |
| `docker-logs` | View all logs |
| `docker-health` | Check container health |
| `docker-shell` | Open shell in app container |
| `docker-db-shell` | Open psql shell |
| `docker-clean` | Remove all containers and volumes |
| `secrets-generate` | Generate new secrets |
| `secrets-validate` | Validate secrets exist |

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs <service-name>

# Validate configuration
docker-compose config

# Check health
make docker-health
```

### Database connection issues
```bash
# Open database shell
make docker-db-shell

# Check if database is ready
docker-compose exec postgres pg_isready
```

### NATS connection issues
```bash
# Check NATS status
curl http://localhost:8222/varz

# View NATS logs
make docker-logs-natss
```

### Vault unseal (production)
```bash
# Check status
docker-compose exec vault vault status

# Unseal if needed
docker-compose exec vault vault operator unseal
```

## Environment Variables

Application requires these environment variables (set in docker-compose.yml):

- `DATABASE_URL`: PostgreSQL connection string
- `NATS_URL`: NATS server URL
- `VAULT_URL`: Vault server URL
- `VAULT_TOKEN`: Vault authentication token
- `SECRET_KEY`: Application secret key
- `ENCRYPTION_KEY`: Data encryption key

## Production Considerations

1. **Replace dev secrets**: Generate secure secrets with `make secrets-generate`
2. **Enable TLS**: Configure TLS for all services
3. **External storage**: Use external volume drivers for production
4. **Monitoring**: Configure Prometheus/Grafana integration
5. **Backup**: Implement backup strategy for PostgreSQL and Vault
6. **High availability**: Use docker-compose.prod.yml for HA configuration
7. **Secret rotation**: Implement regular secret rotation with Vault
