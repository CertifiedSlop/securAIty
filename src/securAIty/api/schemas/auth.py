from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, Field, ConfigDict


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255, description="Username or email address")
    password: str = Field(min_length=8, max_length=128, description="User password")

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str = Field(description="JWT access token")
    refresh_token: str = Field(description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Access token expiration time in seconds")
    expires_at: datetime = Field(description="Access token expiration timestamp")

    model_config = ConfigDict(from_attributes=True)


class TokenRefreshRequest(BaseModel):
    refresh_token: str = Field(description="Valid refresh token")

    model_config = ConfigDict(from_attributes=True)


class TokenData(BaseModel):
    sub: str = Field(description="Subject (username or user ID)")
    exp: datetime = Field(description="Expiration time")
    iat: datetime = Field(description="Issued at time")
    jti: str = Field(description="JWT ID for token uniqueness")
    type: str = Field(description="Token type (access or refresh)")
    roles: Optional[List[str]] = Field(default=None, description="User roles for authorization")
    permissions: Optional[List[str]] = Field(default=None, description="User permissions")

    model_config = ConfigDict(from_attributes=True)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=8, max_length=128, description="Current password")
    new_password: str = Field(min_length=8, max_length=128, description="New password")

    model_config = ConfigDict(from_attributes=True)


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=1, max_length=255, description="User email address")

    model_config = ConfigDict(from_attributes=True)


class PasswordResetConfirm(BaseModel):
    token: str = Field(description="Password reset token")
    new_password: str = Field(min_length=8, max_length=128, description="New password")

    model_config = ConfigDict(from_attributes=True)
