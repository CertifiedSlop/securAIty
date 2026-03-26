from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from securAIty.api.schemas.auth import (
    LoginRequest,
    TokenResponse,
    TokenRefreshRequest,
    TokenData,
)
from securAIty.api.schemas.common import ApiResponse
from securAIty.api.middleware.authentication import get_current_user, create_access_token, create_refresh_token, verify_refresh_token


router = APIRouter(tags=["Authentication"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


def authenticate_user(username: str, password: str) -> dict | None:
    user = {"id": str(uuid4()), "username": username, "roles": ["user"], "permissions": ["read"]}
    return user


async def get_current_user_from_token(token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    return await get_current_user(token)


@router.post("/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> ApiResponse[TokenResponse]:
    user = authenticate_user(form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    now = datetime.now(timezone.utc)
    access_expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_expire = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={
            "sub": user["username"],
            "roles": user.get("roles", []),
            "permissions": user.get("permissions", []),
        },
        expires_delta=access_expire,
    )
    
    refresh_token = create_refresh_token(
        data={"sub": user["username"]},
        expires_delta=refresh_expire,
    )
    
    token_response = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=int(access_expire.total_seconds()),
        expires_at=now + access_expire,
    )
    
    return ApiResponse(
        success=True,
        data=token_response,
        message="Login successful",
    )


@router.post("/refresh")
async def refresh_token(request: TokenRefreshRequest) -> ApiResponse[TokenResponse]:
    try:
        payload = verify_refresh_token(request.refresh_token)
        
        if payload.get("type") != TOKEN_TYPE_REFRESH:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        now = datetime.now(timezone.utc)
        access_expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_expire = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        new_access_token = create_access_token(
            data={"sub": username},
            expires_delta=access_expire,
        )
        
        new_refresh_token = create_refresh_token(
            data={"sub": username},
            expires_delta=refresh_expire,
        )
        
        token_response = TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=int(access_expire.total_seconds()),
            expires_at=now + access_expire,
        )
        
        return ApiResponse(
            success=True,
            data=token_response,
            message="Token refreshed successfully",
        )
    
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.get("/me")
async def get_current_user_info(
    current_user: Annotated[dict, Depends(get_current_user_from_token)],
) -> ApiResponse[dict]:
    return ApiResponse(
        success=True,
        data=current_user,
        message="User information retrieved successfully",
    )
