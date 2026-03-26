# API Overview

The securAIty REST API provides programmatic access to security event management, incident response, and agent orchestration capabilities.

## Base URL

```
/api/v1/
```

All API endpoints are prefixed with `/api/v1/`. Version increments indicate breaking changes.

## API Architecture

```mermaid
graph TB
    Client[Client Application] --> LB[Load Balancer]
    LB --> API[API Gateway /api/v1/]
    
    subgraph "Authentication Layer"
        API --> Auth[Auth Middleware]
        Auth --> JWT[JWT Handler]
        Auth --> RBAC[RBAC Checker]
    end
    
    subgraph "API Routes"
        API --> Health[Health Endpoints]
        API --> AuthRoutes[Auth Endpoints]
        API --> Events[Events Endpoints]
        API --> Incidents[Incidents Endpoints]
        API --> Agents[Agents Endpoints]
    end
    
    subgraph "Backend Services"
        Events --> EventStore[Event Store]
        Incidents --> IncidentStore[Incident Store]
        Agents --> AgentStore[Agent Store]
        AgentStore --> NATS[NATS Message Bus]
    end
    
    subgraph "Data Layer"
        EventStore --> DB[(PostgreSQL)]
        IncidentStore --> DB
        AgentStore --> DB
        JWT --> Vault[HashiCorp Vault]
    end
```

## Authentication

All API endpoints except health checks require authentication using JWT Bearer tokens.

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Auth
    participant Vault

    Client->>API: POST /api/v1/auth/login<br/>username, password
    API->>Auth: Validate credentials
    Auth->>Vault: Verify user exists
    Vault-->>Auth: User data + roles
    Auth->>Auth: Generate JWT access token (15min)
    Auth->>Auth: Generate JWT refresh token (7 days)
    Auth-->>API: Token pair
    API-->>Client: 200 OK + tokens

    Note over Client,API: Access protected resources
    Client->>API: GET /api/v1/events<br/>Authorization: Bearer <token>
    API->>API: Validate JWT signature
    API->>API: Check expiration
    API-->>Client: 200 OK + data

    Note over Client,API: Token refresh
    Client->>API: POST /api/v1/auth/refresh<br/>refresh_token
    API->>API: Validate refresh token
    API->>API: Issue new token pair
    API-->>Client: 200 OK + new tokens
```

### Token Format

| Token Type | Lifetime | Purpose |
|------------|----------|---------|
| Access Token | 15 minutes | API request authorization |
| Refresh Token | 7 days | Obtain new access tokens |

### Authorization Header

```http
Authorization: Bearer <access_token>
```

## Rate Limiting

securAIty implements sliding window rate limiting to prevent API abuse.

### Default Limits

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Authentication | 10 requests | 1 minute |
| Health checks | Unlimited | - |
| Standard API | 100 requests | 1 minute |
| Bulk operations | 20 requests | 1 minute |

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1711468800
```

### Rate Limit Response (429)

```json
{
  "type": "https://httpstatuses.com/429",
  "title": "Too Many Requests",
  "status": 429,
  "detail": "Rate limit exceeded. Try again in 45 seconds.",
  "instance": "/api/v1/events"
}
```

## Error Handling

The API follows [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457) (Problem Details for HTTP APIs) for error responses.

### Error Response Format

```json
{
  "type": "https://api.securAIty.com/errors/validation-error",
  "title": "Validation Error",
  "status": 400,
  "detail": "Request validation failed",
  "instance": "/api/v1/events",
  "errors": [
    {
      "field": "severity",
      "message": "Value must be one of: low, medium, high, critical"
    }
  ]
}
```

### Standard Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `VALIDATION_ERROR` | Invalid request format or parameters |
| 401 | `UNAUTHORIZED` | Missing or invalid authentication |
| 403 | `FORBIDDEN` | Insufficient permissions |
| 404 | `NOT_FOUND` | Resource not found |
| 409 | `CONFLICT` | Resource conflict (e.g., duplicate) |
| 429 | `RATE_LIMITED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Server error |
| 503 | `SERVICE_UNAVAILABLE` | Service temporarily unavailable |

### Error Type URIs

| Error Type | URI |
|------------|-----|
| Validation Error | `https://api.securAIty.com/errors/validation-error` |
| Authentication Error | `https://api.securAIty.com/errors/auth-error` |
| Authorization Error | `https://api.securAIty.com/errors/forbidden` |
| Not Found | `https://api.securAIty.com/errors/not-found` |
| Rate Limit | `https://api.securAIty.com/errors/rate-limit` |
| Internal Error | `https://api.securAIty.com/errors/internal` |

## Request/Response Format

### Content Type

```http
Content-Type: application/json
Accept: application/json
```

### Character Encoding

All requests and responses use UTF-8 encoding.

### Request Example

```http
POST /api/v1/events HTTP/1.1
Host: api.securAIty.com
Content-Type: application/json
Accept: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "event_type": "security_alert",
  "severity": "high",
  "source": "ids-sensor-01",
  "title": "Suspicious network activity detected",
  "description": "Multiple failed SSH login attempts from 192.168.1.100"
}
```

### Response Example

```http
HTTP/1.1 201 Created
Content-Type: application/json
X-Request-Id: req_abc123

{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "event_type": "security_alert",
    "severity": "high",
    "source": "ids-sensor-01",
    "title": "Suspicious network activity detected",
    "description": "Multiple failed SSH login attempts from 192.168.1.100",
    "status": "new",
    "occurred_at": "2024-03-26T10:30:00Z",
    "created_at": "2024-03-26T10:31:00Z"
  },
  "message": "Event created successfully",
  "timestamp": "2024-03-26T10:31:00Z"
}
```

## Pagination

List endpoints return paginated responses.

### Request Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number (1-indexed) |
| `page_size` | integer | 20 | Items per page (max 100) |

### Response Format

```json
{
  "success": true,
  "data": {
    "items": [...],
    "total": 150,
    "page": 1,
    "page_size": 20,
    "total_pages": 8
  },
  "message": "Retrieved 20 events",
  "timestamp": "2024-03-26T10:31:00Z"
}
```

## CORS

Cross-Origin Resource Sharing is configurable via environment variables.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | `[]` | Comma-separated list of allowed origins |
| `CORS_ALLOW_CREDENTIALS` | `false` | Allow credentials in CORS requests |
| `CORS_ALLOWED_METHODS` | `["*"]` | Allowed HTTP methods |
| `CORS_ALLOWED_HEADERS` | `["*"]` | Allowed HTTP headers |

### Example Configuration

```bash
CORS_ALLOWED_ORIGINS=https://app.securAIty.com,https://admin.securAIty.com
CORS_ALLOW_CREDENTIALS=true
CORS_ALLOWED_METHODS=GET,POST,PUT,PATCH,DELETE
CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Request-Id
```

## Health Endpoints

Health endpoints do not require authentication.

| Endpoint | Description |
|----------|-------------|
| `GET /health/live` | Liveness probe - is the API running? |
| `GET /health/ready` | Readiness probe - is the API ready to serve traffic? |

### Liveness Response

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2024-03-26T10:30:00Z",
    "version": "0.1.0",
    "services": {
      "api": "operational",
      "database": "unknown",
      "nats": "unknown",
      "vault": "unknown"
    }
  },
  "message": "Service is healthy"
}
```

### Readiness Response

```json
{
  "success": true,
  "data": {
    "ready": true,
    "timestamp": "2024-03-26T10:30:00Z",
    "checks": {
      "database_connection": true,
      "nats_connection": true,
      "vault_connection": true,
      "agents_connected": true
    }
  },
  "message": "Service is ready"
}
```

## API Versioning

The API uses URL-based versioning (`/api/v1/`). Version changes occur when:

- Breaking changes to request/response schemas
- Endpoint removal or path changes
- Authentication/authorization behavior changes

Non-breaking changes (new optional fields, new endpoints) do not require version bumps.

## Related Documentation

- [Endpoints Reference](endpoints.md) - Complete endpoint documentation
- [Schemas Reference](schemas.md) - Request/response schema definitions
- [Authentication Guide](authentication.md) - JWT and RBAC details
