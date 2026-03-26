from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
import os

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

from securAIty.api.schemas.auth import TokenData
from securAIty.security.exceptions import SecurityInitializationError, JWTDecodeError
from securAIty.security import JWTHandler, TokenRevocationStore, TokenClaims


JWT_HANDLER_INSTANCE: Optional[JWTHandler] = None
REVOCATION_STORE: Optional[TokenRevocationStore] = None


def get_jwt_handler() -> JWTHandler:
    global JWT_HANDLER_INSTANCE
    if JWT_HANDLER_INSTANCE is None:
        private_key_path = os.getenv("JWT_PRIVATE_KEY_PATH")
        public_key_path = os.getenv("JWT_PUBLIC_KEY_PATH")
        
        if private_key_path and os.path.exists(private_key_path):
            with open(private_key_path, "rb") as f:
                private_key_pem = f.read()
            
            public_key_pem = None
            if public_key_path and os.path.exists(public_key_path):
                with open(public_key_path, "rb") as f:
                    public_key_pem = f.read()
            
            JWT_HANDLER_INSTANCE = JWTHandler.from_keys(
                private_key_pem=private_key_pem,
                public_key_pem=public_key_pem,
                issuer="securAIty",
                audience="securAIty-api",
            )
        else:
            JWT_HANDLER_INSTANCE = JWTHandler(
                issuer="securAIty",
                audience="securAIty-api",
            )
    
    return JWT_HANDLER_INSTANCE


def get_revocation_store() -> TokenRevocationStore:
    global REVOCATION_STORE
    if REVOCATION_STORE is None:
        REVOCATION_STORE = TokenRevocationStore()
    return REVOCATION_STORE


ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"

security = HTTPBearer(auto_error=False)


class JWTConfiguration(BaseModel):
    algorithm: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    issuer: str
    audience: str

    @classmethod
    def from_env(cls) -> "JWTConfiguration":
        return cls(
            algorithm="RS256",
            access_token_expire_minutes=int(os.getenv("JWT_EXPIRATION_MINUTES", "30")),
            refresh_token_expire_days=7,
            issuer=os.getenv("JWT_ISSUER", "securAIty"),
            audience=os.getenv("JWT_AUDIENCE", "securAIty-api"),
        )


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    jwt_handler = get_jwt_handler()
    
    user_id = data.get("sub", data.get("user_id", ""))
    roles = data.get("roles", [])
    permissions = data.get("permissions", [])
    session_id = data.get("session_id")
    
    lifetime = expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    return jwt_handler.create_access_token(
        user_id=user_id,
        roles=roles,
        permissions=permissions,
        session_id=session_id,
        lifetime=lifetime,
    )


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    jwt_handler = get_jwt_handler()
    
    user_id = data.get("sub", data.get("user_id", ""))
    session_id = data.get("session_id")
    
    lifetime = expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    return jwt_handler.create_refresh_token(
        user_id=user_id,
        session_id=session_id,
        lifetime=lifetime,
    )


def decode_token(token: str, expected_type: str) -> Dict[str, Any]:
    jwt_handler = get_jwt_handler()
    
    try:
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header.get("alg") != "RS256":
            raise JWTDecodeError(f"Invalid algorithm: {unverified_header.get('alg')}")
        
        claims = jwt_handler.decode_token(token, verify_exp=True)
        
        if claims.type != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return claims.to_dict()
        
    except JWTDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def decode_token_with_revocation_check(token: str, expected_type: str) -> Dict[str, Any]:
    jwt_handler = get_jwt_handler()
    revocation_store = get_revocation_store()
    
    try:
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header.get("alg") != "RS256":
            raise JWTDecodeError(f"Invalid algorithm: {unverified_header.get('alg')}")
        
        claims = await jwt_handler.verify_token_async(token, verify_exp=True)
        
        is_revoked = await revocation_store.is_revoked(claims.jti)
        if is_revoked:
            raise JWTDecodeError("Token has been revoked")
        
        if claims.type != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return claims.to_dict()
        
    except JWTDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def verify_refresh_token(refresh_token: str) -> Dict[str, Any]:
    return decode_token(refresh_token, TOKEN_TYPE_REFRESH)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    payload = await decode_token_with_revocation_check(token, TOKEN_TYPE_ACCESS)

    username = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = TokenData(
        sub=username,
        exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
        jti=payload["jti"],
        type=payload["type"],
        roles=payload.get("roles"),
        permissions=payload.get("permissions"),
    )

    return {
        "id": str(uuid4()),
        "username": username,
        "roles": token_data.roles or [],
        "permissions": token_data.permissions or [],
    }


def require_permission(required_permission: str):
    async def permission_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_permissions = current_user.get("permissions", [])
        user_roles = current_user.get("roles", [])

        if "admin" in user_roles:
            return current_user

        if required_permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied",
            )

        return current_user

    return permission_checker


def require_role(required_role: str):
    async def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_roles = current_user.get("roles", [])

        if required_role not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Role access denied",
            )

        return current_user

    return role_checker
