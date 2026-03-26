# API Schemas

**Author:** CertifiedSlop

Complete reference for all Pydantic schemas used in securAIty API requests and responses.

## Schema Conventions

- All schemas use Pydantic v2 with `ConfigDict` for configuration
- Response schemas use `from_attributes=True` for ORM compatibility
- All timestamps use ISO 8601 format with UTC timezone
- UUIDs are string-formatted (e.g., `550e8400-e29b-41d4-a716-446655440000`)

---

## Authentication Schemas

### LoginRequest

User login credentials.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `username` | string | Yes | 1-255 chars | Username or email address |
| `password` | string | Yes | 8-128 chars | User password |

**JSON Example:**

```json
{
  "username": "admin@securAIty.com",
  "password": "SecurePassword123!"
}
```

---

### TokenResponse

JWT token pair response.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `access_token` | string | Yes | JWT access token |
| `refresh_token` | string | Yes | JWT refresh token |
| `token_type` | string | No | Token type (default: `bearer`) |
| `expires_in` | integer | Yes | Access token expiration in seconds |
| `expires_at` | datetime | Yes | Access token expiration timestamp |

**JSON Example:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "expires_at": "2024-03-26T11:00:00Z"
}
```

---

### TokenRefreshRequest

Token refresh request.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `refresh_token` | string | Yes | Valid refresh token |

**JSON Example:**

```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### TokenData

JWT token claims structure.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sub` | string | Yes | Subject (username or user ID) |
| `exp` | datetime | Yes | Expiration time |
| `iat` | datetime | Yes | Issued at time |
| `jti` | string | Yes | JWT ID for token uniqueness |
| `type` | string | Yes | Token type (`access` or `refresh`) |
| `roles` | string[] | No | User roles for authorization |
| `permissions` | string[] | No | User permissions |

**JSON Example (decoded JWT payload):**

```json
{
  "sub": "admin@securAIty.com",
  "exp": 1711468800,
  "iat": 1711465200,
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "type": "access",
  "roles": ["admin"],
  "permissions": ["read", "write", "delete", "admin"]
}
```

---

### PasswordChangeRequest

Password change request.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `current_password` | string | Yes | 8-128 chars | Current password |
| `new_password` | string | Yes | 8-128 chars | New password |

---

### PasswordResetRequest

Password reset initiation.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `email` | string | Yes | 1-255 chars | User email address |

---

### PasswordResetConfirm

Password reset confirmation.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `token` | string | Yes | - | Password reset token |
| `new_password` | string | Yes | 8-128 chars | New password |

---

## Event Schemas

### Event Types

Valid event type values:

| Value | Description |
|-------|-------------|
| `security_alert` | Security alert from monitoring systems |
| `intrusion_detected` | Intrusion detection system alert |
| `malware_detected` | Malware detection event |
| `unauthorized_access` | Unauthorized access attempt |
| `data_breach` | Data breach or exfiltration |
| `policy_violation` | Security policy violation |
| `system_anomaly` | System behavior anomaly |
| `threat_intelligence` | External threat intelligence |
| `audit_log` | Audit log event |
| `custom` | Custom event type |

---

### EventSeverity

Valid severity levels:

| Value | Description |
|-------|-------------|
| `low` | Low severity |
| `medium` | Medium severity |
| `high` | High severity |
| `critical` | Critical severity |

---

### EventBase

Base schema for security events.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `event_type` | string | Yes | Enum (see Event Types) | Type of security event |
| `severity` | string | Yes | Enum (`low`, `medium`, `high`, `critical`) | Severity level |
| `source` | string | Yes | 1-255 chars | Source system identifier |
| `title` | string | Yes | 1-500 chars | Brief event title |
| `description` | string | Yes | 1-5000 chars | Detailed description |

---

### EventCreate

Schema for creating events.

Extends `EventBase` with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `metadata` | object | No | Additional metadata |
| `occurred_at` | datetime | No | Event occurrence time (default: now) |

**JSON Example:**

```json
{
  "event_type": "security_alert",
  "severity": "high",
  "source": "ids-sensor-01",
  "title": "Suspicious network activity detected",
  "description": "Multiple failed SSH login attempts from 192.168.1.100",
  "metadata": {
    "source_ip": "192.168.1.100",
    "attempts": 15,
    "target_port": 22
  },
  "occurred_at": "2024-03-26T10:30:00Z"
}
```

---

### EventUpdate

Schema for updating events.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | string | No | Updated severity level |
| `title` | string | No | Updated title |
| `description` | string | No | Updated description |
| `metadata` | object | No | Updated metadata |
| `status` | string | No | Updated status |

---

### EventResponse

Schema for event responses.

Extends `EventBase` with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes | Unique event identifier |
| `status` | string | Yes | Event status (default: `new`) |
| `occurred_at` | datetime | Yes | When the event occurred |
| `created_at` | datetime | Yes | When the event was recorded |
| `updated_at` | datetime | No | When the event was last updated |
| `metadata` | object | No | Event metadata |
| `related_incident_id` | UUID | No | Related incident ID if any |

**JSON Example:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "security_alert",
  "severity": "high",
  "source": "ids-sensor-01",
  "title": "Suspicious network activity detected",
  "description": "Multiple failed SSH login attempts from 192.168.1.100",
  "status": "new",
  "occurred_at": "2024-03-26T10:30:00Z",
  "created_at": "2024-03-26T10:31:00Z",
  "updated_at": null,
  "metadata": {
    "source_ip": "192.168.1.100",
    "attempts": 15
  },
  "related_incident_id": null
}
```

---

### EventFilter

Schema for filtering events.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | No | Filter by event type |
| `severity` | string | No | Filter by severity |
| `source` | string | No | Filter by source |
| `status` | string | No | Filter by status |
| `start_date` | datetime | No | Filter from date |
| `end_date` | datetime | No | Filter until date |
| `search` | string | No | Search in title/description (max 255 chars) |

---

## Incident Schemas

### IncidentStatus

Valid incident statuses:

| Value | Description |
|-------|-------------|
| `new` | Newly created incident |
| `investigating` | Under investigation |
| `contained` | Threat contained |
| `resolved` | Incident resolved |
| `closed` | Incident closed |

---

### IncidentPriority

Valid priority levels:

| Value | Description |
|-------|-------------|
| `low` | Low priority |
| `medium` | Medium priority |
| `high` | High priority |
| `critical` | Critical priority |

---

### IncidentCategory

Valid incident categories:

| Value | Description |
|-------|-------------|
| `malware` | Malware infection |
| `phishing` | Phishing attack |
| `ransomware` | Ransomware attack |
| `data_breach` | Data breach |
| `insider_threat` | Insider threat |
| `ddos` | DDoS attack |
| `unauthorized_access` | Unauthorized access |
| `policy_violation` | Policy violation |
| `other` | Other category |

---

### IncidentBase

Base schema for incidents.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `title` | string | Yes | 1-500 chars | Brief incident title |
| `description` | string | Yes | 1-10000 chars | Detailed description |
| `category` | string | Yes | Enum (see Categories) | Incident category |
| `priority` | string | Yes | Enum (see Priorities) | Priority level |
| `status` | string | No | Enum (see Statuses) | Status (default: `new`) |

---

### IncidentCreate

Schema for creating incidents.

Extends `IncidentBase` with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `assigned_to` | string | No | User or team assignee (max 255 chars) |
| `related_event_ids` | UUID[] | No | Related event IDs |
| `metadata` | object | No | Additional metadata |

**JSON Example:**

```json
{
  "title": "Data exfiltration attempt",
  "description": "Large outbound data transfer to suspicious IP detected",
  "category": "data_breach",
  "priority": "critical",
  "status": "new",
  "assigned_to": "security-team",
  "related_event_ids": [
    "550e8400-e29b-41d4-a716-446655440000",
    "550e8400-e29b-41d4-a716-446655440001"
  ],
  "metadata": {
    "target_ip": "203.0.113.50",
    "data_volume_mb": 500
  }
}
```

---

### IncidentUpdate

Schema for updating incidents.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `title` | string | No | 1-500 chars | Updated title |
| `description` | string | No | 1-10000 chars | Updated description |
| `category` | string | No | Enum | Updated category |
| `priority` | string | No | Enum | Updated priority |
| `status` | string | No | Enum | Updated status |
| `assigned_to` | string | No | Max 255 chars | Updated assignee |
| `resolution_notes` | string | No | Max 5000 chars | Resolution notes |
| `metadata` | object | No | - | Updated metadata |

---

### IncidentResponse

Schema for incident responses.

Extends `IncidentBase` with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes | Unique incident identifier |
| `assigned_to` | string | No | User or team assignee |
| `related_event_ids` | UUID[] | Yes | Related event IDs (default: empty) |
| `created_at` | datetime | Yes | When incident was created |
| `updated_at` | datetime | No | When incident was last updated |
| `resolved_at` | datetime | No | When incident was resolved |
| `resolution_notes` | string | No | Resolution notes |
| `metadata` | object | No | Incident metadata |

**JSON Example:**

```json
{
  "id": "660f9511-f3ac-52e5-b827-557766551111",
  "title": "Data exfiltration attempt",
  "description": "Large outbound data transfer to suspicious IP",
  "category": "data_breach",
  "priority": "critical",
  "status": "contained",
  "assigned_to": "security-team",
  "related_event_ids": [
    "550e8400-e29b-41d4-a716-446655440000"
  ],
  "created_at": "2024-03-26T09:00:00Z",
  "updated_at": "2024-03-26T09:30:00Z",
  "resolved_at": null,
  "resolution_notes": null,
  "metadata": {
    "target_ip": "203.0.113.50"
  }
}
```

---

### IncidentFilter

Schema for filtering incidents.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | string | No | Filter by status |
| `priority` | string | No | Filter by priority |
| `category` | string | No | Filter by category |
| `assigned_to` | string | No | Filter by assignee |
| `search` | string | No | Search in title/description (max 255 chars) |
| `start_date` | datetime | No | Filter from date |
| `end_date` | datetime | No | Filter until date |

---

## Agent Schemas

### AgentStatus

Valid agent statuses:

| Value | Description |
|-------|-------------|
| `online` | Agent is online and operational |
| `offline` | Agent is offline |
| `busy` | Agent is processing tasks |
| `degraded` | Agent is running with reduced capacity |
| `maintenance` | Agent is under maintenance |

---

### AgentType

Valid agent types:

| Value | Description |
|-------|-------------|
| `threat_detection` | Threat detection agent |
| `vulnerability_scanner` | Vulnerability scanning agent |
| `incident_response` | Incident response agent |
| `log_analyzer` | Log analysis agent |
| `compliance_checker` | Compliance checking agent |
| `malware_analyzer` | Malware analysis agent |
| `network_monitor` | Network monitoring agent |
| `custom` | Custom agent type |

---

### AgentCapabilities

Agent capabilities definition.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `supported_event_types` | string[] | No | - | Event types agent can handle |
| `max_concurrent_tasks` | integer | No | Min: 1 | Max concurrent tasks (default: 5) |
| `supported_actions` | string[] | No | - | Actions agent can perform |
| `version` | string | Yes | - | Agent version |
| `metadata` | object | No | - | Additional capability metadata |

**JSON Example:**

```json
{
  "supported_event_types": ["security_alert", "intrusion_detected"],
  "max_concurrent_tasks": 10,
  "supported_actions": ["scan", "block", "isolate"],
  "version": "1.2.3",
  "metadata": {
    "signature_database": "2024-03-26",
    "ml_model_version": "v2.1"
  }
}
```

---

### AgentBase

Base schema for agents.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `name` | string | Yes | 1-255 chars | Human-readable agent name |
| `agent_type` | string | Yes | Enum (see AgentType) | Agent type |
| `description` | string | Yes | 1-1000 chars | Agent description |

---

### AgentRegister

Schema for registering agents.

Extends `AgentBase` with:

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `capabilities` | object | Yes | AgentCapabilities | Agent capabilities |
| `host` | string | Yes | 1-255 chars | Agent host |
| `port` | integer | No | 1-65535 | Agent port |

**JSON Example:**

```json
{
  "name": "threat-detector-01",
  "agent_type": "threat_detection",
  "description": "Primary threat detection agent for production network",
  "capabilities": {
    "supported_event_types": ["security_alert", "intrusion_detected"],
    "max_concurrent_tasks": 10,
    "supported_actions": ["scan", "block"],
    "version": "1.2.3"
  },
  "host": "192.168.1.50",
  "port": 8443
}
```

---

### AgentResponse

Schema for agent responses.

Extends `AgentBase` with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes | Unique agent identifier |
| `status` | string | Yes | Current agent status |
| `capabilities` | object | Yes | Agent capabilities |
| `host` | string | Yes | Agent host |
| `port` | integer | No | Agent port |
| `registered_at` | datetime | Yes | Registration timestamp |
| `last_heartbeat` | datetime | No | Last heartbeat timestamp |

---

### AgentHeartbeat

Schema for agent heartbeat submissions.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `status` | string | Yes | Enum (see AgentStatus) | Current status |
| `cpu_usage` | number | No | 0-100 | CPU usage percentage |
| `memory_usage` | number | No | 0-100 | Memory usage percentage |
| `active_tasks` | integer | No | Min: 0 | Active task count |
| `completed_tasks` | integer | No | Min: 0 | Total completed tasks |
| `failed_tasks` | integer | No | Min: 0 | Total failed tasks |
| `metadata` | object | No | - | Additional heartbeat data |

**JSON Example:**

```json
{
  "status": "online",
  "cpu_usage": 45.2,
  "memory_usage": 62.8,
  "active_tasks": 3,
  "completed_tasks": 1250,
  "failed_tasks": 5,
  "metadata": {
    "queue_depth": 10,
    "last_scan": "2024-03-26T10:30:00Z"
  }
}
```

---

### AgentStatusResponse

Schema for agent health status responses.

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `agent_id` | UUID | Yes | - | Agent unique identifier |
| `status` | string | Yes | Enum | Current status |
| `last_heartbeat` | datetime | Yes | - | Last heartbeat timestamp |
| `cpu_usage` | number | No | - | CPU usage percentage |
| `memory_usage` | number | No | - | Memory usage percentage |
| `active_tasks` | integer | Yes | - | Active task count |
| `health_score` | number | Yes | 0-100 | Overall health score |
| `is_responsive` | boolean | Yes | - | Is agent responding |

**JSON Example:**

```json
{
  "agent_id": "770g0622-g4bd-63f6-c938-668877662222",
  "status": "online",
  "last_heartbeat": "2024-03-26T10:35:00Z",
  "cpu_usage": 45.2,
  "memory_usage": 62.8,
  "active_tasks": 3,
  "health_score": 87.5,
  "is_responsive": true
}
```

---

## Common Schemas

### PaginatedRequest

Pagination parameters for list endpoints.

| Field | Type | Default | Validation | Description |
|-------|------|---------|------------|-------------|
| `page` | integer | 1 | Min: 1 | Page number (1-indexed) |
| `page_size` | integer | 20 | 1-100 | Items per page |

---

### PaginatedResponse

Paginated response wrapper.

| Field | Type | Description |
|-------|------|-------------|
| `items` | array | List of items on current page |
| `total` | integer | Total items across all pages |
| `page` | integer | Current page number |
| `page_size` | integer | Items per page |
| `total_pages` | integer | Total number of pages |

**JSON Example:**

```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "page_size": 20,
  "total_pages": 8
}
```

---

### ApiResponse

Standard API response wrapper.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `success` | boolean | `true` | Request success indicator |
| `data` | any | `null` | Response data payload |
| `message` | string | `null` | Optional message |
| `timestamp` | datetime | `now` | Response timestamp |

**JSON Example (success):**

```json
{
  "success": true,
  "data": {...},
  "message": "Operation completed successfully",
  "timestamp": "2024-03-26T10:30:00Z"
}
```

**JSON Example (error):**

```json
{
  "success": false,
  "data": null,
  "message": "Invalid request parameters",
  "timestamp": "2024-03-26T10:30:00Z"
}
```

---

### ErrorResponse

RFC 9457 Problem Details error response.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `error_code` | string | Yes | Machine-readable error code |
| `message` | string | Yes | Human-readable message |
| `details` | object | No | Additional error details |
| `path` | string | Yes | Request path that caused error |
| `timestamp` | datetime | Yes | Error timestamp |

**JSON Example:**

```json
{
  "error_code": "VALIDATION_ERROR",
  "message": "Request validation failed",
  "details": {
    "errors": [
      {
        "field": "severity",
        "message": "Value must be one of: low, medium, high, critical"
      }
    ]
  },
  "path": "/api/v1/events",
  "timestamp": "2024-03-26T10:30:00Z"
}
```

---

### HealthResponse

Health check response.

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Overall status (`healthy`, `unhealthy`) |
| `timestamp` | datetime | Check timestamp |
| `version` | string | API version |
| `services` | object | Service status map |

**JSON Example:**

```json
{
  "status": "healthy",
  "timestamp": "2024-03-26T10:30:00Z",
  "version": "0.1.0",
  "services": {
    "api": "operational",
    "database": "operational",
    "nats": "operational",
    "vault": "operational"
  }
}
```

---

### ReadinessResponse

Readiness check response.

| Field | Type | Description |
|-------|------|-------------|
| `ready` | boolean | Readiness status |
| `timestamp` | datetime | Check timestamp |
| `checks` | object | Individual check results |

**JSON Example:**

```json
{
  "ready": true,
  "timestamp": "2024-03-26T10:30:00Z",
  "checks": {
    "database_connection": true,
    "nats_connection": true,
    "vault_connection": true,
    "agents_connected": true
  }
}
```

---

## Related Documentation

- [API Overview](overview.md) - Architecture and authentication
- [Endpoints Reference](endpoints.md) - Complete endpoint documentation
- [Authentication Guide](authentication.md) - JWT and RBAC details

---

&copy; 2026 CertifiedSlop. All rights reserved.
