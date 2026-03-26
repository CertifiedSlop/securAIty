# Authentication Guide

Comprehensive guide to securAIty authentication, authorization, and token management.

## Overview

securAIty uses JWT (JSON Web Tokens) with RS256 asymmetric signing for authentication. The system implements a dual-token architecture with short-lived access tokens and long-lived refresh tokens.

---

## JWT Token Structure

### Token Format

```
header.payload.signature
```

### Header

```json
{
  "typ": "JWT",
  "alg": "RS256"
}
```

| Field | Value | Description |
|-------|-------|-------------|
| `typ` | `JWT` | Token type |
| `alg` | `RS256` | Signing algorithm (RSA-PSS with SHA-256) |

---

### Access Token Payload

```json
{
  "sub": "admin@securAIty.com",
  "iat": 1711465200,
  "exp": 1711466100,
  "nbf": 1711465170,
  "iss": "securAIty",
  "aud": "securAIty-api",
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "type": "access",
  "roles": ["admin"],
  "permissions": ["read", "write", "delete", "admin"],
  "session_id": "sess_abc123"
}
```

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | Subject (username or user ID) |
| `iat` | integer | Issued at timestamp (Unix epoch) |
| `exp` | integer | Expiration timestamp (Unix epoch) |
| `nbf` | integer | Not valid before timestamp |
| `iss` | string | Issuer (`securAIty`) |
| `aud` | string | Audience (`securAIty-api`) |
| `jti` | string | Unique token identifier (UUID) |
| `type` | string | Token type (`access`) |
| `roles` | string[] | User roles for RBAC |
| `permissions` | string[] | Explicit permissions |
| `session_id` | string | Session tracking identifier |

---

### Refresh Token Payload

```json
{
  "sub": "admin@securAIty.com",
  "iat": 1711465200,
  "exp": 1712070000,
  "nbf": 1711465170,
  "iss": "securAIty",
  "aud": "securAIty-api",
  "jti": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "type": "refresh",
  "session_id": "sess_abc123"
}
```

**Note:** Refresh tokens do not include `roles` or `permissions` claims. These are re-evaluated on token refresh.

---

## Token Lifecycle

### Token Generation Flow

```mermaid
sequenceDiagram
    participant User
    participant API
    participant Auth
    participant Vault

    User->>API: POST /auth/login (credentials)
    API->>Auth: Validate credentials
    Auth->>Vault: Verify user + fetch roles
    Vault-->>Auth: User data + roles + permissions
    Auth->>Auth: Generate access token (15 min)
    Auth->>Auth: Generate refresh token (7 days)
    Auth-->>API: Token pair
    API-->>User: 200 OK + tokens
```

### Token Usage Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant JWT

    Client->>API: Request with Bearer token
    API->>JWT: Verify signature (RS256)
    JWT-->>API: Valid signature
    API->>API: Check expiration (exp)
    API->>API: Check revocation (jti)
    API->>API: Validate claims (iss, aud)
    API->>API: Check RBAC permissions
    API-->>Client: 200 OK + data
```

### Token Refresh Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Auth
    participant Vault

    Client->>API: POST /auth/refresh (refresh_token)
    API->>Auth: Validate refresh token
    Auth->>Auth: Verify signature + expiration
    Auth->>Vault: Fetch current user roles
    Vault-->>Auth: Updated roles/permissions
    Auth->>Auth: Generate new access token
    Auth->>Auth: Generate new refresh token (rotation)
    Auth-->>API: New token pair
    API-->>Client: 200 OK + new tokens
```

---

## Token Lifetimes

| Token Type | Lifetime | Configurable |
|------------|----------|--------------|
| Access Token | 15 minutes | Yes (via `JWT_EXPIRATION_MINUTES`) |
| Refresh Token | 7 days | Fixed |

### Clock Skew Tolerance

A 30-second clock skew tolerance is applied to expiration checks to account for clock drift between servers.

---

## RBAC (Role-Based Access Control)

### Standard Roles

| Role | Description | Default Permissions |
|------|-------------|---------------------|
| `admin` | Full system access | All permissions |
| `analyst` | Security analysis and incident response | read, write |
| `viewer` | Read-only access | read |

### Permission Matrix

| Permission | Admin | Analyst | Viewer | Description |
|------------|-------|---------|--------|-------------|
| `read` | ✓ | ✓ | ✓ | View resources |
| `write` | ✓ | ✓ | ✗ | Create/update resources |
| `delete` | ✓ | ✗ | ✗ | Delete resources |
| `admin` | ✓ | ✗ | ✗ | Administrative actions |
| `users:manage` | ✓ | ✗ | ✗ | User management |
| `agents:manage` | ✓ | ✓ | ✗ | Agent registration/control |
| `incidents:manage` | ✓ | ✓ | ✗ | Incident lifecycle |
| `events:manage` | ✓ | ✓ | ✗ | Event management |
| `audit:read` | ✓ | ✓ | ✓ | View audit logs |
| `config:read` | ✓ | ✓ | ✗ | View configuration |
| `config:write` | ✓ | ✗ | ✗ | Modify configuration |

### Endpoint Authorization

| Endpoint | Required Role | Required Permission |
|----------|---------------|---------------------|
| `GET /health/*` | - | - (public) |
| `POST /auth/login` | - | - (public) |
| `POST /auth/refresh` | - | - (uses refresh token) |
| `POST /auth/logout` | Any | - (authenticated) |
| `GET /auth/me` | Any | - (authenticated) |
| `GET /events` | viewer | `read` |
| `POST /events` | analyst | `write` |
| `DELETE /events/{id}` | admin | `delete` |
| `GET /incidents` | viewer | `read` |
| `POST /incidents` | analyst | `write` |
| `PATCH /incidents/{id}` | analyst | `write` |
| `POST /incidents/{id}/assign` | analyst | `incidents:manage` |
| `POST /incidents/{id}/resolve` | analyst | `incidents:manage` |
| `GET /agents` | analyst | `read` |
| `POST /agents` | admin | `agents:manage` |
| `GET /agents/{id}/health` | analyst | `read` |
| `POST /agents/{id}/action` | admin | `agents:manage` |

---

## Token Refresh

### When to Refresh

Refresh tokens should be used when:

1. Access token expires (401 response with `token_expired` error)
2. Proactively before expiration (recommended: refresh at 80% of lifetime)
3. After receiving `invalid_token` error

### Refresh Best Practices

```python
import requests
import time
from datetime import datetime, timezone

class AuthenticatedClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
    
    def login(self, username, password):
        """Authenticate and store tokens."""
        response = requests.post(
            f"{self.base_url}/auth/login",
            data={"username": username, "password": password}
        )
        tokens = response.json()["data"]
        self.access_token = tokens["access_token"]
        self.refresh_token = tokens["refresh_token"]
        self.token_expires_at = datetime.fromisoformat(
            tokens["expires_at"].replace("Z", "+00:00")
        )
    
    def _ensure_valid_token(self):
        """Refresh token if expired or near expiration."""
        if not self.access_token:
            self._refresh()
            return
        
        # Refresh 2 minutes before expiration
        buffer = 120  # seconds
        expires_soon = (
            self.token_expires_at - datetime.now(timezone.utc)
        ).total_seconds() < buffer
        
        if expires_soon:
            self._refresh()
    
    def _refresh(self):
        """Obtain new token pair using refresh token."""
        if not self.refresh_token:
            raise ValueError("No refresh token available")
        
        response = requests.post(
            f"{self.base_url}/auth/refresh",
            json={"refresh_token": self.refresh_token}
        )
        tokens = response.json()["data"]
        self.access_token = tokens["access_token"]
        self.refresh_token = tokens["refresh_token"]
        self.token_expires_at = datetime.fromisoformat(
            tokens["expires_at"].replace("Z", "+00:00")
        )
    
    def request(self, method, path, **kwargs):
        """Make authenticated request with automatic token refresh."""
        self._ensure_valid_token()
        
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.access_token}"
        
        response = requests.request(
            method,
            f"{self.base_url}{path}",
            headers=headers,
            **kwargs
        )
        
        # Handle token expiration
        if response.status_code == 401:
            self._refresh()
            headers["Authorization"] = f"Bearer {self.access_token}"
            response = requests.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                **kwargs
            )
        
        return response
```

---

## Token Revocation

### Single Token Revocation

Revoke a specific access token (e.g., on logout):

```bash
curl -X POST https://api.securAIty.com/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Full Session Revocation

Revoke all tokens for a user (logout everywhere):

```bash
curl -X POST https://api.securAIty.com/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"revoke_all": true}'
```

### Revocation Implementation

The revocation system uses a token store that tracks revoked JWT IDs (jti):

```python
# Token revocation check (performed on each request)
async def verify_token(token: str) -> TokenClaims:
    claims = jwt_handler.decode_token(token)
    
    # Check if token JTI is in revocation store
    if await revocation_store.is_revoked(claims.jti):
        raise JWTRevokedError("Token has been revoked")
    
    return claims
```

### Revocation Store Cleanup

Revoked tokens are automatically cleaned up after their original expiration time to prevent unbounded growth.

---

## Security Considerations

### Token Storage

**Client-side:**

| Storage Method | Security Level | Recommendation |
|----------------|----------------|----------------|
| HttpOnly cookie | High | Recommended for web apps |
| Memory (JavaScript variable) | Medium | Good for SPAs, lost on refresh |
| localStorage | Low | Vulnerable to XSS, not recommended |
| sessionStorage | Low-Medium | Cleared on tab close |

**Server-side:**

- Access tokens: Not stored (stateless validation)
- Refresh tokens: Stored in revocation store for validation
- Revoked JTI list: Stored with automatic cleanup

### Token Protection

1. **Always use HTTPS** - Tokens must never travel over unencrypted connections
2. **Short access token lifetime** - Limits exposure window
3. **Refresh token rotation** - New refresh token issued on each refresh
4. **Token binding** - Session ID ties tokens to specific session
5. **Revocation on sensitive actions** - Revoke tokens after password change

### Brute Force Protection

Authentication endpoints implement rate limiting:

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/auth/login` | 10 requests | 1 minute |
| `/auth/refresh` | 30 requests | 1 minute |

### Account Lockout

After 5 consecutive failed login attempts within 15 minutes:

1. Account is temporarily locked for 30 minutes
2. All existing tokens are revoked
3. Lockout event is logged to audit system

---

## Error Responses

### 401 Unauthorized

```json
{
  "type": "https://api.securAIty.com/errors/auth-error",
  "title": "Unauthorized",
  "status": 401,
  "detail": "Invalid or expired token",
  "instance": "/api/v1/events"
}
```

**Causes:**
- Missing Authorization header
- Invalid token signature
- Expired token
- Revoked token

### 403 Forbidden

```json
{
  "type": "https://api.securAIty.com/errors/forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "Missing required permission: incidents:manage",
  "instance": "/api/v1/incidents/abc123/assign"
}
```

**Causes:**
- Valid token but insufficient permissions
- User lacks required role

---

## Implementation Reference

### JWT Handler (Python)

```python
from securAIty.security.jwt_handler import JWTHandler, TokenClaims

# Initialize handler (keys loaded from Vault in production)
jwt_handler = JWTHandler(
    issuer="securAIty",
    audience="securAIty-api"
)

# Create token pair
token_pair = jwt_handler.create_token_pair(
    user_id="admin@securAIty.com",
    roles=["admin"],
    permissions=["read", "write", "delete", "admin"],
    session_id="sess_abc123"
)

# Validate token
try:
    claims = await jwt_handler.verify_token_async(token_pair.access_token)
    print(f"User: {claims.user_id}, Roles: {claims.roles}")
except JWTExpiredError:
    print("Token has expired")
except JWTRevokedError:
    print("Token has been revoked")
except JWTDecodeError as e:
    print(f"Invalid token: {e}")
```

### Middleware Integration

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    token = credentials.credentials
    
    try:
        claims = await jwt_handler.verify_token_async(token)
    except JWTExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTRevokedError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except JWTDecodeError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return {
        "user_id": claims.user_id,
        "roles": claims.roles,
        "permissions": claims.permissions
    }


def require_permission(permission: str):
    async def checker(current_user: dict = Depends(get_current_user)):
        if "admin" in current_user["roles"]:
            return current_user
        
        if permission not in current_user["permissions"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}"
            )
        return current_user
    return checker
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_EXPIRATION_MINUTES` | `30` | Access token lifetime in minutes |
| `JWT_ALGORITHM` | `HS256` | Signing algorithm (use RS256 in production) |
| `JWT_ISSUER` | `securAIty` | Token issuer claim |
| `JWT_AUDIENCE` | `securAIty-api` | Token audience claim |
| `JWT_CLOCK_SKEW_SECONDS` | `30` | Allowed clock skew tolerance |

### Production Key Management

In production, RSA keys should be:

1. Generated externally using strong entropy
2. Stored in HashiCorp Vault
3. Rotated periodically (recommended: every 90 days)
4. Private key never leaves Vault boundary

```bash
# Generate RSA key pair (OpenSSL)
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in private.pem -out public.pem

# Import to Vault
vault kv put secret/jwt/private key=@private.pem
vault kv put secret/jwt/public key=@public.pem
```

---

## Related Documentation

- [API Overview](overview.md) - Architecture and error handling
- [Endpoints Reference](endpoints.md) - Authentication endpoints
- [Schemas Reference](schemas.md) - Token and auth schemas
