"""

Pydantic schemas for 2FA endpoints.
"""

from pydantic import BaseModel, field_validator


class TwoFactorSetupResponse(BaseModel):
    """Returned when 2FA setup is initiated."""
    secret: str       # Raw TOTP secret for manual entry
    qr_code: str      # Base64-encoded PNG QR code image
    qr_uri: str       # The otpauth:// URI


class TwoFactorConfirmRequest(BaseModel):
    """User sends a 6-digit code to confirm they scanned the QR."""
    totp_code: str

    @field_validator("totp_code")
    @classmethod
    def validate_totp_code(cls, v: str) -> str:
        v = v.strip().replace(" ", "")
        if not v.isdigit() or len(v) != 6:
            raise ValueError("TOTP code must be exactly 6 digits.")
        return v


class TwoFactorVerifyRequest(BaseModel):
    """
    Sent to complete login when 2FA is required.
    temp_token proves the user passed password verification.
    """
    temp_token: str
    totp_code: str

    @field_validator("totp_code")
    @classmethod
    def validate_totp_code(cls, v: str) -> str:
        v = v.strip().replace(" ", "")
        if not v.isdigit() or len(v) != 6:
            raise ValueError("TOTP code must be exactly 6 digits.")
        return v


class TwoFactorDisableRequest(BaseModel):
    """User must provide current TOTP code to disable 2FA."""
    totp_code: str

    @field_validator("totp_code")
    @classmethod
    def validate_totp_code(cls, v: str) -> str:
        v = v.strip().replace(" ", "")
        if not v.isdigit() or len(v) != 6:
            raise ValueError("TOTP code must be exactly 6 digits.")
        return v


class TwoFactorLoginResponse(BaseModel):
    """Full JWT response after successful 2FA verification."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: dict        