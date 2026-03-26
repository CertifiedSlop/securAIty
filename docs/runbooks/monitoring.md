# Monitoring Runbook

**Purpose**: Observability setup for securAIty platform including metrics, logs, and alerting.

**Audience**: SRE team, DevOps engineers, on-call engineers

**Last Updated**: 2026-03-26

---

## Table of Contents

1. [Health Check Endpoints](#health-check-endpoints)
2. [Metrics Collection](#metrics-collection)
3. [Log Aggregation](#log-aggregation)
4. [Alerting Rules](#alerting-rules)
5. [Dashboard Setup](#dashboard-setup)
6. [SLO/SLI Definitions](#slisli-definitions)
7. [Troubleshooting Guide](#troubleshooting-guide)

---

## Health Check Endpoints

### Endpoint Overview

| Endpoint | Method | Purpose | Frequency |
|----------|--------|---------|-----------|
| `/api/v1/health/live` | GET | Liveness probe | 10s |
| `/api/v1/health/ready` | GET | Readiness probe | 30s |
| `/api/v1/health/complete` | GET | Full health check | 60s |

### Liveness Probe

```bash
curl http://localhost:8000/api/v1/health/live

# Response: 200 OK
{
  "status": "healthy",
  "timestamp": "2026-03-26T14:30:00Z"
}
```

### Readiness Probe

```bash
curl http://localhost:8000/api/v1/health/ready

# Response: 200 OK
{
  "status": "ready",
  "checks": {
    "database": "healthy",
    "nats": "healthy",
    "vault": "healthy",
    "agents": "healthy"
  },
  "timestamp": "2026-03-26T14:30:00Z"
}
```

### Complete Health Check

```bash
curl http://localhost:8000/api/v1/health/complete

# Response: 200 OK
{
  "status": "healthy",
  "subsystems": {
    "database": {
      "status": "healthy",
      "latency_ms": 2.5,
      "connections": {"active": 10, "max": 100}
    },
    "nats": {
      "status": "healthy",
      "latency_ms": 0.8,
      "pending_messages": 150
    },
    "vault": {
      "status": "healthy",
      "sealed": false,
      "ha_enabled": false
    },
    "agents": {
      "status": "healthy",
      "online": 5,
      "total": 5
    }
  },
  "timestamp": "2026-03-26T14:30:00Z"
}
```

---

## Metrics Collection

### Prometheus Configuration

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'securAIty'
    static_configs:
      - targets: ['app:8000']
    metrics_path: '/metrics'
    
  - job_name: 'nats'
    static_configs:
      - targets: ['nats:8222']
    metrics_path: '/metrics'
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
      
  - job_name: 'vault'
    static_configs:
      - targets: ['vault:8200']
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']
```

### Application Metrics

The securAIty application exposes the following Prometheus metrics:

```python
# HTTP Metrics
http_requests_total{method, endpoint, status}
http_request_duration_seconds{method, endpoint, quantile}
http_requests_in_flight{method, endpoint}

# Database Metrics
db_connections_total{state}  # active, idle, max
db_query_duration_seconds{query_type, quantile}
db_errors_total{error_type}

# NATS Metrics
nats_messages_published_total{subject}
nats_messages_consumed_total{subject}
nats_message_size_bytes{subject, quantile}
nats_connection_state{state}  # connected, disconnected, reconnecting

# Agent Metrics
agent_status{agent_name, status}  # online, offline, busy, unhealthy
agent_events_processed_total{agent_name}
agent_event_processing_duration_seconds{agent_name, quantile}
agent_errors_total{agent_name, error_type}

# Security Metrics
security_events_total{type, severity}
incidents_total{status, severity}
auth_attempts_total{status}  # success, failure
tokens_issued_total{type}  # access, refresh
tokens_revoked_total

# Vault Metrics
vault_secrets_read_total{path}
vault_secrets_write_total{path}
vault_token_renewals_total
vault_lease_renewals_total
```

### Custom Metrics Endpoint

```python
# Example: Access metrics programmatically
import requests

response = requests.get('http://localhost:8000/metrics')
print(response.text)
```

---

## Log Aggregation

### Log Format

securAIty uses structured JSON logging:

```json
{
  "timestamp": "2026-03-26T14:30:00.123Z",
  "level": "INFO",
  "logger": "securAIty.api.auth",
  "message": "User login successful",
  "correlation_id": "abc-123-def",
  "user_id": "user-456",
  "ip_address": "192.168.1.100",
  "duration_ms": 45.2
}
```

### ELK Stack Configuration

**Logstash Pipeline** (`logstash.conf`):

```conf
input {
  tcp {
    port => 5000
    codec => json_lines
  }
}

filter {
  if [logger] =~ /^securAIty/ {
    mutate {
      add_tag => ["securAIty"]
    }
  }
  
  date {
    match => ["timestamp", "ISO8601"]
    target => "@timestamp"
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "securAIty-%{+YYYY.MM.dd}"
  }
}
```

### Loki Configuration

**loki-config.yaml**:

```yaml
auth_enabled: false

server:
  http_listen_port: 3100

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules

schema_config:
  configs:
    - from: 2026-01-01
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

limits_config:
  retention_period: 168h  # 7 days
```

### Log Query Examples

**Find all errors in last hour**:
```
{logger=~"securAIty.*"} |= "ERROR" | __error__=""
```

**Find slow API requests (>1s)**:
```
{logger=~"securAIty.api.*"} | json | duration_ms > 1000
```

**Find failed authentication attempts**:
```
{logger=~"securAIty.api.auth.*"} | json | message =~ "failed|invalid|denied"
```

**Find security events by severity**:
```
{logger=~"securAIty.events.*"} | json | severity = "critical"
```

---

## Alerting Rules

### Prometheus Alertmanager Configuration

**alerts.yml**:

```yaml
groups:
  - name: securAIty
    rules:
      # Application Health
      - alert: AppDown
        expr: up{job="securAIty"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "securAIty application is down"
          description: "Application instance {{ $labels.instance }} has been down for more than 1 minute."

      # High Error Rate
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }}% (threshold: 5%)"

      # Database Connection Pool Exhaustion
      - alert: DBConnectionPoolExhausted
        expr: db_connections_total{state="active"} / db_connections_total{state="max"} > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool nearly exhausted"
          description: "{{ $value * 100 }}% of connections in use"

      # NATS Pending Messages
      - alert: NATSPendingMessagesHigh
        expr: nats_pending_messages > 10000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "NATS pending messages high"
          description: "{{ $value }} messages pending (threshold: 10000)"

      # Agent Offline
      - alert: AgentOffline
        expr: agent_status{status="offline"} == 1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Security agent offline"
          description: "Agent {{ $labels.agent_name }} has been offline for more than 2 minutes"

      # Vault Sealed
      - alert: VaultSealed
        expr: vault_sealed == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Vault is sealed"
          description: "HashiCorp Vault requires unsealing"

      # High Authentication Failures
      - alert: HighAuthFailures
        expr: rate(auth_attempts_total{status="failure"}[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }} failed auth attempts per second"

      # Critical Security Event
      - alert: CriticalSecurityEvent
        expr: rate(security_events_total{severity="critical"}[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Critical security event detected"
          description: "Event type: {{ $labels.type }}"

      # Token Revocation Spike
      - alert: TokenRevocationSpike
        expr: rate(tokens_revoked_total[5m]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Unusual token revocation activity"
          description: "{{ $value }} tokens revoked per second"
```

### Alertmanager Routing

```yaml
route:
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'default'
  
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
    - match:
        severity: warning
      receiver: 'slack-warnings'

receivers:
  - name: 'default'
    email_configs:
      - to: 'security-team@example.com'
        
  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: '<pagerduty-service-key>'
        
  - name: 'slack-warnings'
    slack_configs:
      - api_url: '<slack-webhook-url>'
        channel: '#security-alerts'
```

---

## Dashboard Setup

### Grafana Dashboard Template

**securAIty-overview.json**:

```json
{
  "dashboard": {
    "title": "securAIty Overview",
    "panels": [
      {
        "title": "Application Health",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job='securAIty'}",
            "legendFormat": "Status"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "mappings": [
              {"type": "value", "options": {"0": {"text": "DOWN", "color": "red"}}},
              {"type": "value", "options": {"1": {"text": "UP", "color": "green"}}}
            ]
          }
        }
      },
      {
        "title": "HTTP Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Agent Status",
        "type": "table",
        "targets": [
          {
            "expr": "agent_status",
            "legendFormat": "{{agent_name}}: {{status}}"
          }
        ]
      },
      {
        "title": "Security Events by Severity",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum(security_events_total) by (severity)",
            "legendFormat": "{{severity}}"
          }
        ]
      },
      {
        "title": "Incident Trends",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(incidents_total[1h])",
            "legendFormat": "{{status}}"
          }
        ]
      },
      {
        "title": "NATS Message Throughput",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(nats_messages_published_total[5m])",
            "legendFormat": "Published"
          },
          {
            "expr": "rate(nats_messages_consumed_total[5m])",
            "legendFormat": "Consumed"
          }
        ]
      }
    ],
    "time": {"from": "now-1h", "to": "now"},
    "refresh": "30s"
  }
}
```

### Import Dashboard

```bash
# Using Grafana API
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <grafana-token>" \
  -d @securAIty-overview.json
```

---

## SLO/SLI Definitions

### Service Level Indicators (SLIs)

| Metric | Measurement | Target |
|--------|-------------|--------|
| Availability | Successful health checks / Total checks | 99.9% |
| Latency (p95) | API response time | < 500ms |
| Latency (p99) | API response time | < 1000ms |
| Error Rate | 5xx responses / Total requests | < 0.1% |
| Agent Uptime | Agent online time / Total time | 99.5% |
| Event Delivery | Events delivered / Events published | 99.99% |

### Service Level Objectives (SLOs)

```yaml
slo_definitions:
  - name: API Availability
    target: 99.9%
    window: 30d
    sli: availability
    
  - name: API Latency
    target: 95% of requests < 500ms
    window: 7d
    sli: latency_p95
    
  - name: Agent Reliability
    target: 99.5%
    window: 30d
    sli: agent_uptime
    
  - name: Event Delivery
    target: 99.99%
    window: 7d
    sli: event_delivery
```

### Error Budget

| SLO | Target | Monthly Error Budget |
|-----|--------|---------------------|
| API Availability | 99.9% | 43m 49s downtime |
| API Latency p95 | 500ms | 5% of requests can exceed |
| Agent Uptime | 99.5% | 3h 36m offline time |

---

## Troubleshooting Guide

### High Latency

**Symptoms**: API response time > 1s

**Diagnosis**:
```bash
# Check p95 latency
curl http://localhost:8000/metrics | grep http_request_duration

# Check database query times
docker compose logs app | grep "query_duration" | tail -20

# Check NATS pending messages
curl http://localhost:8222/varz | jq '.pending'
```

**Resolution**:
1. Scale application replicas
2. Increase database connection pool
3. Check for slow queries in logs
4. Review agent processing times

### High Error Rate

**Symptoms**: Error rate > 5%

**Diagnosis**:
```bash
# Check error logs
docker compose logs app | grep "ERROR" | tail -50

# Check specific error types
curl http://localhost:8000/metrics | grep http_requests_total | grep "5.."
```

**Resolution**:
1. Review application logs for stack traces
2. Check database connectivity
3. Verify Vault connection
4. Check agent health status

### Agent Offline

**Symptoms**: One or more agents showing offline

**Diagnosis**:
```bash
# Check agent status
curl http://localhost:8000/api/v1/agents

# Check agent logs
docker compose logs app | grep "agent.*offline"
```

**Resolution**:
1. Restart affected agent via API
2. Check agent configuration
3. Review NATS connectivity
4. Check resource constraints

### Vault Issues

**Symptoms**: Vault sealed or unreachable

**Diagnosis**:
```bash
# Check Vault status
docker compose exec vault vault status

# Check Vault logs
docker compose logs vault | tail -50
```

**Resolution**:
1. Unseal Vault if sealed
2. Verify Vault token validity
3. Check network connectivity
4. Review Vault policies

---

## Next Steps

1. [Set Up Backups](backup-recovery.md)
2. [Configure Incident Response](incident-response.md)
3. [Review Security Hardening](security-hardening.md)

---

**Document Version**: 1.0  
**Maintained By**: securAIty SRE Team
