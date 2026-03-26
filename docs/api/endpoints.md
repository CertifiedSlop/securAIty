# API Endpoints

Complete reference for all securAIty API endpoints.

## Base URL

```
/api/v1
```

---

## Health Endpoints

Public endpoints for monitoring and orchestration. No authentication required.

### GET /health/live

Liveness probe indicating the API server is running.

**Authentication:** Not required

**Response Schema:** `ApiResponse<HealthStatus>`

| Status Code | Description |
|-------------|-------------|
| 200 | Service is alive |
| 500 | Service is unhealthy |

**curl Example:**

```bash
curl -s https://api.securAIty.com/api/v1/health/live
```

**Python Example:**

```python
import requests

response = requests.get("https://api.securAIty.com/api/v1/health/live")
print(response.json())
```

**Response:**

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
  "message": "Service is healthy",
  "timestamp": "2024-03-26T10:30:00Z"
}
```

---

### GET /health/ready

Readiness probe indicating the API is ready to serve traffic.

**Authentication:** Not required

**Response Schema:** `ApiResponse<ReadinessStatus>`

| Status Code | Description |
|-------------|-------------|
| 200 | Service is ready |
| 503 | Service is not ready |

**curl Example:**

```bash
curl -s https://api.securAIty.com/api/v1/health/ready
```

**Python Example:**

```python
import requests

response = requests.get("https://api.securAIty.com/api/v1/health/ready")
print(response.json())
```

**Response:**

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
  "message": "Service is ready",
  "timestamp": "2024-03-26T10:30:00Z"
}
```

---

## Authentication Endpoints

User authentication and token management.

### POST /auth/login

Authenticate user and obtain JWT token pair.

**Authentication:** Not required

**Request Schema:** `LoginRequest`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Username or email (1-255 chars) |
| `password` | string | Yes | User password (8-128 chars) |

**Response Schema:** `ApiResponse<TokenResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Authentication successful |
| 400 | Invalid request format |
| 401 | Invalid credentials |
| 429 | Too many requests |
| 500 | Server error |

**curl Example:**

```bash
curl -X POST https://api.securAIty.com/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@securAIty.com" \
  -d "password=SecurePassword123!"
```

**Python Example:**

```python
import requests

response = requests.post(
    "https://api.securAIty.com/api/v1/auth/login",
    data={
        "username": "admin@securAIty.com",
        "password": "SecurePassword123!"
    }
)
tokens = response.json()["data"]
access_token = tokens["access_token"]
print(f"Access token: {access_token}")
```

**Response:**

```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 1800,
    "expires_at": "2024-03-26T11:00:00Z"
  },
  "message": "Login successful",
  "timestamp": "2024-03-26T10:30:00Z"
}
```

---

### POST /auth/refresh

Refresh access token using a valid refresh token.

**Authentication:** Not required (uses refresh token)

**Request Schema:** `TokenRefreshRequest`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `refresh_token` | string | Yes | Valid refresh token |

**Response Schema:** `ApiResponse<TokenResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Token refreshed successfully |
| 400 | Invalid request format |
| 401 | Invalid or expired refresh token |
| 500 | Server error |

**curl Example:**

```bash
curl -X POST https://api.securAIty.com/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

**Python Example:**

```python
import requests

response = requests.post(
    "https://api.securAIty.com/api/v1/auth/refresh",
    json={"refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
)
tokens = response.json()["data"]
print(f"New access token: {tokens['access_token']}")
```

**Response:**

```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 1800,
    "expires_at": "2024-03-26T11:15:00Z"
  },
  "message": "Token refreshed successfully",
  "timestamp": "2024-03-26T10:45:00Z"
}
```

---

### POST /auth/logout

Invalidate current token and optionally all user tokens.

**Authentication:** Required (Bearer token)

**Request Schema:** Optional body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `revoke_all` | boolean | No | Revoke all user tokens (default: false) |

**Response Schema:** `ApiResponse<null>`

| Status Code | Description |
|-------------|-------------|
| 200 | Logout successful |
| 401 | Invalid or missing token |
| 500 | Server error |

**curl Example:**

```bash
curl -X POST https://api.securAIty.com/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"revoke_all": true}'
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
response = requests.post(
    "https://api.securAIty.com/api/v1/auth/logout",
    headers=headers,
    json={"revoke_all": True}
)
print(response.json())
```

**Response:**

```json
{
  "success": true,
  "data": null,
  "message": "Logout successful. All tokens revoked.",
  "timestamp": "2024-03-26T10:45:00Z"
}
```

---

### GET /auth/me

Get current authenticated user information.

**Authentication:** Required (Bearer token)

**Roles:** Any authenticated user

**Response Schema:** `ApiResponse<UserInfo>`

| Status Code | Description |
|-------------|-------------|
| 200 | User info retrieved |
| 401 | Invalid or missing token |
| 500 | Server error |

**curl Example:**

```bash
curl https://api.securAIty.com/api/v1/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
response = requests.get("https://api.securAIty.com/api/v1/auth/me", headers=headers)
user = response.json()["data"]
print(f"User: {user['username']}, Roles: {user['roles']}")
```

**Response:**

```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "admin@securAIty.com",
    "roles": ["admin"],
    "permissions": ["read", "write", "delete", "admin"]
  },
  "message": "User information retrieved successfully",
  "timestamp": "2024-03-26T10:30:00Z"
}
```

---

## Events Endpoints

Security event management.

### GET /events

List security events with filtering and pagination.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`, `viewer`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `page_size` | integer | 20 | Items per page (max 100) |
| `event_type` | string | - | Filter by event type |
| `severity` | string | - | Filter by severity |
| `source` | string | - | Filter by source |
| `status` | string | - | Filter by status |
| `start_date` | datetime | - | Filter from date |
| `end_date` | datetime | - | Filter until date |
| `search` | string | - | Search in title/description |

**Response Schema:** `ApiResponse<PaginatedResponse<EventResponse>>`

| Status Code | Description |
|-------------|-------------|
| 200 | Events retrieved |
| 400 | Invalid filter parameters |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 500 | Server error |

**curl Example:**

```bash
curl "https://api.securAIty.com/api/v1/events?page=1&page_size=10&severity=high&status=new" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
params = {
    "page": 1,
    "page_size": 10,
    "severity": "high",
    "status": "new"
}
response = requests.get("https://api.securAIty.com/api/v1/events", headers=headers, params=params)
events = response.json()["data"]
print(f"Total: {events['total']}, Page: {events['page']}")
```

**Response:**

```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "event_type": "security_alert",
        "severity": "high",
        "source": "ids-sensor-01",
        "title": "Suspicious network activity",
        "description": "Multiple failed SSH attempts",
        "status": "new",
        "occurred_at": "2024-03-26T10:30:00Z",
        "created_at": "2024-03-26T10:31:00Z",
        "metadata": {"source_ip": "192.168.1.100"}
      }
    ],
    "total": 45,
    "page": 1,
    "page_size": 10,
    "total_pages": 5
  },
  "message": "Retrieved 10 events",
  "timestamp": "2024-03-26T10:35:00Z"
}
```

---

### POST /events

Create a new security event.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`

**Request Schema:** `EventCreate`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | Yes | Event type (see [Schemas](schemas.md#event-types)) |
| `severity` | string | Yes | Severity: `low`, `medium`, `high`, `critical` |
| `source` | string | Yes | Source system (max 255 chars) |
| `title` | string | Yes | Brief title (max 500 chars) |
| `description` | string | Yes | Detailed description (max 5000 chars) |
| `metadata` | object | No | Additional metadata |
| `occurred_at` | datetime | No | Event occurrence time (default: now) |

**Response Schema:** `ApiResponse<EventResponse>`

| Status Code | Description |
|-------------|-------------|
| 201 | Event created |
| 400 | Invalid request format |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 500 | Server error |

**curl Example:**

```bash
curl -X POST https://api.securAIty.com/api/v1/events \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "security_alert",
    "severity": "high",
    "source": "ids-sensor-01",
    "title": "Suspicious network activity detected",
    "description": "Multiple failed SSH login attempts from 192.168.1.100",
    "metadata": {"source_ip": "192.168.1.100", "attempts": 15}
  }'
```

**Python Example:**

```python
import requests
from datetime import datetime, timezone

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
event = {
    "event_type": "security_alert",
    "severity": "high",
    "source": "ids-sensor-01",
    "title": "Suspicious network activity detected",
    "description": "Multiple failed SSH login attempts",
    "metadata": {"source_ip": "192.168.1.100"}
}
response = requests.post(
    "https://api.securAIty.com/api/v1/events",
    headers=headers,
    json=event
)
created = response.json()["data"]
print(f"Event created: {created['id']}")
```

**Response:**

```json
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
    "created_at": "2024-03-26T10:31:00Z",
    "metadata": {"source_ip": "192.168.1.100", "attempts": 15}
  },
  "message": "Event created successfully",
  "timestamp": "2024-03-26T10:31:00Z"
}
```

---

### GET /events/{event_id}

Get a specific security event by ID.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`, `viewer`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_id` | UUID | Event unique identifier |

**Response Schema:** `ApiResponse<EventResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Event retrieved |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Event not found |
| 500 | Server error |

**curl Example:**

```bash
curl https://api.securAIty.com/api/v1/events/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
event_id = "550e8400-e29b-41d4-a716-446655440000"
response = requests.get(
    f"https://api.securAIty.com/api/v1/events/{event_id}",
    headers=headers
)
event = response.json()["data"]
print(f"Event: {event['title']}, Status: {event['status']}")
```

**Response:**

```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "event_type": "security_alert",
    "severity": "high",
    "source": "ids-sensor-01",
    "title": "Suspicious network activity detected",
    "description": "Multiple failed SSH login attempts",
    "status": "investigating",
    "occurred_at": "2024-03-26T10:30:00Z",
    "created_at": "2024-03-26T10:31:00Z",
    "updated_at": "2024-03-26T10:35:00Z",
    "metadata": {"source_ip": "192.168.1.100"}
  },
  "message": "Event retrieved successfully",
  "timestamp": "2024-03-26T10:36:00Z"
}
```

---

### DELETE /events/{event_id}

Delete a security event.

**Authentication:** Required (Bearer token)

**Roles:** `admin`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_id` | UUID | Event unique identifier |

**Response Schema:** `ApiResponse<null>`

| Status Code | Description |
|-------------|-------------|
| 200 | Event deleted |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Event not found |
| 500 | Server error |

**curl Example:**

```bash
curl -X DELETE https://api.securAIty.com/api/v1/events/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
event_id = "550e8400-e29b-41d4-a716-446655440000"
response = requests.delete(
    f"https://api.securAIty.com/api/v1/events/{event_id}",
    headers=headers
)
print(response.json()["message"])
```

**Response:**

```json
{
  "success": true,
  "data": null,
  "message": "Event deleted successfully",
  "timestamp": "2024-03-26T10:40:00Z"
}
```

---

## Incidents Endpoints

Security incident management and response.

### GET /incidents

List security incidents with filtering and pagination.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`, `viewer`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `page_size` | integer | 20 | Items per page (max 100) |
| `status` | string | - | Filter by status |
| `priority` | string | - | Filter by priority |
| `category` | string | - | Filter by category |
| `assigned_to` | string | - | Filter by assignee |
| `search` | string | - | Search in title/description |
| `start_date` | datetime | - | Filter from date |
| `end_date` | datetime | - | Filter until date |

**Response Schema:** `ApiResponse<PaginatedResponse<IncidentResponse>>`

| Status Code | Description |
|-------------|-------------|
| 200 | Incidents retrieved |
| 400 | Invalid filter parameters |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 500 | Server error |

**curl Example:**

```bash
curl "https://api.securAIty.com/api/v1/incidents?page=1&status=investigating&priority=high" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
params = {"page": 1, "status": "investigating", "priority": "high"}
response = requests.get(
    "https://api.securAIty.com/api/v1/incidents",
    headers=headers,
    params=params
)
incidents = response.json()["data"]
print(f"Total incidents: {incidents['total']}")
```

**Response:**

```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "660f9511-f3ac-52e5-b827-557766551111",
        "title": "Data exfiltration attempt",
        "description": "Large data transfer detected to external IP",
        "category": "data_breach",
        "priority": "critical",
        "status": "investigating",
        "assigned_to": "security-team",
        "related_event_ids": ["550e8400-e29b-41d4-a716-446655440000"],
        "created_at": "2024-03-26T09:00:00Z",
        "updated_at": "2024-03-26T09:30:00Z",
        "metadata": {"target_ip": "203.0.113.50"}
      }
    ],
    "total": 12,
    "page": 1,
    "page_size": 20,
    "total_pages": 1
  },
  "message": "Retrieved 1 incidents",
  "timestamp": "2024-03-26T10:35:00Z"
}
```

---

### POST /incidents

Create a new security incident.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`

**Request Schema:** `IncidentCreate`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | string | Yes | Brief title (max 500 chars) |
| `description` | string | Yes | Detailed description (max 10000 chars) |
| `category` | string | Yes | Incident category |
| `priority` | string | Yes | Priority level |
| `status` | string | No | Initial status (default: `new`) |
| `assigned_to` | string | No | Assignee user/team |
| `related_event_ids` | UUID[] | No | Related event IDs |
| `metadata` | object | No | Additional metadata |

**Response Schema:** `ApiResponse<IncidentResponse>`

| Status Code | Description |
|-------------|-------------|
| 201 | Incident created |
| 400 | Invalid request format |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 500 | Server error |

**curl Example:**

```bash
curl -X POST https://api.securAIty.com/api/v1/incidents \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Data exfiltration attempt",
    "description": "Large outbound data transfer to suspicious IP",
    "category": "data_breach",
    "priority": "critical",
    "assigned_to": "security-team",
    "related_event_ids": ["550e8400-e29b-41d4-a716-446655440000"]
  }'
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
incident = {
    "title": "Data exfiltration attempt",
    "description": "Large outbound data transfer detected",
    "category": "data_breach",
    "priority": "critical",
    "assigned_to": "security-team"
}
response = requests.post(
    "https://api.securAIty.com/api/v1/incidents",
    headers=headers,
    json=incident
)
created = response.json()["data"]
print(f"Incident created: {created['id']}")
```

**Response:**

```json
{
  "success": true,
  "data": {
    "id": "660f9511-f3ac-52e5-b827-557766551111",
    "title": "Data exfiltration attempt",
    "description": "Large outbound data transfer to suspicious IP",
    "category": "data_breach",
    "priority": "critical",
    "status": "new",
    "assigned_to": "security-team",
    "related_event_ids": ["550e8400-e29b-41d4-a716-446655440000"],
    "created_at": "2024-03-26T10:30:00Z",
    "updated_at": null,
    "resolved_at": null,
    "resolution_notes": null,
    "metadata": {}
  },
  "message": "Incident created successfully",
  "timestamp": "2024-03-26T10:31:00Z"
}
```

---

### GET /incidents/{incident_id}

Get a specific incident by ID.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`, `viewer`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `incident_id` | UUID | Incident unique identifier |

**Response Schema:** `ApiResponse<IncidentResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Incident retrieved |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Incident not found |
| 500 | Server error |

**curl Example:**

```bash
curl https://api.securAIty.com/api/v1/incidents/660f9511-f3ac-52e5-b827-557766551111 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
incident_id = "660f9511-f3ac-52e5-b827-557766551111"
response = requests.get(
    f"https://api.securAIty.com/api/v1/incidents/{incident_id}",
    headers=headers
)
incident = response.json()["data"]
print(f"Incident: {incident['title']}, Status: {incident['status']}")
```

---

### PATCH /incidents/{incident_id}

Update an incident.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `incident_id` | UUID | Incident unique identifier |

**Request Schema:** `IncidentUpdate`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | string | No | Updated title |
| `description` | string | No | Updated description |
| `category` | string | No | Updated category |
| `priority` | string | No | Updated priority |
| `status` | string | No | Updated status |
| `assigned_to` | string | No | Updated assignee |
| `resolution_notes` | string | No | Resolution notes (max 5000 chars) |
| `metadata` | object | No | Updated metadata |

**Response Schema:** `ApiResponse<IncidentResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Incident updated |
| 400 | Invalid request format |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Incident not found |
| 500 | Server error |

**curl Example:**

```bash
curl -X PATCH https://api.securAIty.com/api/v1/incidents/660f9511-f3ac-52e5-b827-557766551111 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "status": "contained",
    "assigned_to": "incident-response-team"
  }'
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
incident_id = "660f9511-f3ac-52e5-b827-557766551111"
update = {"status": "contained", "assigned_to": "incident-response-team"}
response = requests.patch(
    f"https://api.securAIty.com/api/v1/incidents/{incident_id}",
    headers=headers,
    json=update
)
updated = response.json()["data"]
print(f"Incident status: {updated['status']}")
```

---

### POST /incidents/{incident_id}/assign

Assign an incident to a user or team.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `incident_id` | UUID | Incident unique identifier |

**Request Schema:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `assigned_to` | string | Yes | User or team identifier |

**Response Schema:** `ApiResponse<IncidentResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Incident assigned |
| 400 | Invalid request |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Incident not found |
| 500 | Server error |

**curl Example:**

```bash
curl -X POST https://api.securAIty.com/api/v1/incidents/660f9511-f3ac-52e5-b827-557766551111/assign \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"assigned_to": "john.doe@securAIty.com"}'
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
incident_id = "660f9511-f3ac-52e5-b827-557766551111"
response = requests.post(
    f"https://api.securAIty.com/api/v1/incidents/{incident_id}/assign",
    headers=headers,
    json={"assigned_to": "john.doe@securAIty.com"}
)
print(response.json()["message"])
```

---

### POST /incidents/{incident_id}/resolve

Resolve an incident.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `incident_id` | UUID | Incident unique identifier |

**Request Schema:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resolution_notes` | string | Yes | Resolution description |

**Response Schema:** `ApiResponse<IncidentResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Incident resolved |
| 400 | Invalid request |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Incident not found |
| 500 | Server error |

**curl Example:**

```bash
curl -X POST https://api.securAIty.com/api/v1/incidents/660f9511-f3ac-52e5-b827-557766551111/resolve \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "resolution_notes": "Threat actor blocked, affected systems isolated and patched."
  }'
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
incident_id = "660f9511-f3ac-52e5-b827-557766551111"
response = requests.post(
    f"https://api.securAIty.com/api/v1/incidents/{incident_id}/resolve",
    headers=headers,
    json={"resolution_notes": "Threat actor blocked, systems isolated"}
)
print(response.json()["message"])
```

---

## Agents Endpoints

Security agent registration and management.

### GET /agents

List registered security agents.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `page_size` | integer | 20 | Items per page (max 100) |
| `status` | string | - | Filter by status |
| `agent_type` | string | - | Filter by agent type |

**Response Schema:** `ApiResponse<PaginatedResponse<AgentResponse>>`

| Status Code | Description |
|-------------|-------------|
| 200 | Agents retrieved |
| 400 | Invalid filter parameters |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 500 | Server error |

**curl Example:**

```bash
curl "https://api.securAIty.com/api/v1/agents?status=online&agent_type=threat_detection" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
params = {"status": "online", "agent_type": "threat_detection"}
response = requests.get(
    "https://api.securAIty.com/api/v1/agents",
    headers=headers,
    params=params
)
agents = response.json()["data"]
print(f"Online agents: {len(agents['items'])}")
```

---

### GET /agents/{agent_id}

Get a specific agent by ID.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_id` | UUID | Agent unique identifier |

**Response Schema:** `ApiResponse<AgentResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Agent retrieved |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Agent not found |
| 500 | Server error |

**curl Example:**

```bash
curl https://api.securAIty.com/api/v1/agents/770g0622-g4bd-63f6-c938-668877662222 \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
agent_id = "770g0622-g4bd-63f6-c938-668877662222"
response = requests.get(
    f"https://api.securAIty.com/api/v1/agents/{agent_id}",
    headers=headers
)
agent = response.json()["data"]
print(f"Agent: {agent['name']}, Status: {agent['status']}")
```

---

### GET /agents/{agent_id}/health

Get agent health status.

**Authentication:** Required (Bearer token)

**Roles:** `admin`, `analyst`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_id` | UUID | Agent unique identifier |

**Response Schema:** `ApiResponse<AgentStatusResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Health status retrieved |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Agent not found |
| 500 | Server error |

**curl Example:**

```bash
curl https://api.securAIty.com/api/v1/agents/770g0622-g4bd-63f6-c938-668877662222/health \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
agent_id = "770g0622-g4bd-63f6-c938-668877662222"
response = requests.get(
    f"https://api.securAIty.com/api/v1/agents/{agent_id}/health",
    headers=headers
)
health = response.json()["data"]
print(f"Health score: {health['health_score']}, Responsive: {health['is_responsive']}")
```

**Response:**

```json
{
  "success": true,
  "data": {
    "agent_id": "770g0622-g4bd-63f6-c938-668877662222",
    "status": "online",
    "last_heartbeat": "2024-03-26T10:35:00Z",
    "cpu_usage": 45.2,
    "memory_usage": 62.8,
    "active_tasks": 3,
    "health_score": 87.5,
    "is_responsive": true
  },
  "message": "Agent status retrieved successfully",
  "timestamp": "2024-03-26T10:36:00Z"
}
```

---

### POST /agents/{agent_id}/action

Execute an action on an agent.

**Authentication:** Required (Bearer token)

**Roles:** `admin`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_id` | UUID | Agent unique identifier |

**Request Schema:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | Yes | Action to execute |
| `parameters` | object | No | Action parameters |

**Response Schema:** `ApiResponse<ActionResponse>`

| Status Code | Description |
|-------------|-------------|
| 200 | Action executed |
| 400 | Invalid action or parameters |
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Agent not found |
| 500 | Server error |

**curl Example:**

```bash
curl -X POST https://api.securAIty.com/api/v1/agents/770g0622-g4bd-63f6-c938-668877662222/action \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "action": "scan",
    "parameters": {"target": "192.168.1.0/24", "scan_type": "vulnerability"}
  }'
```

**Python Example:**

```python
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
agent_id = "770g0622-g4bd-63f6-c938-668877662222"
action = {
    "action": "scan",
    "parameters": {"target": "192.168.1.0/24", "scan_type": "vulnerability"}
}
response = requests.post(
    f"https://api.securAIty.com/api/v1/agents/{agent_id}/action",
    headers=headers,
    json=action
)
result = response.json()["data"]
print(f"Task ID: {result['task_id']}")
```

---

## Related Documentation

- [API Overview](overview.md) - Architecture, authentication, error handling
- [Schemas Reference](schemas.md) - Request/response schema definitions
- [Authentication Guide](authentication.md) - JWT and RBAC details
