"""
app/config.py

Central configuration management using Pydantic Settings.
All environment variables are loaded, validated, and typed here.
Any misconfiguration fails loudly at startup — not silently at runtime.
"""

import json
from functools import lru_cache
from typing import List, Literal

from pydantic import AnyHttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Pydantic automatically validates types and raises errors for
    missing required fields. lru_cache ensures this is only
    instantiated once per process lifetime.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,  # APP_NAME and app_name both work
        extra="ignore",        # Don't raise errors for unknown env vars
    )

    # ── Application ──────────────────────────────────────────────
    app_name: str = "AuthShield"
    app_version: str = "1.0.0"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = True

    # ── Server ───────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000

    # ── Database ─────────────────────────────────────────────────
    database_url: str

    # ── Redis ────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── JWT ──────────────────────────────────────────────────────
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # ── CORS ─────────────────────────────────────────────────────
    # Stored as a JSON string in .env, parsed into a list here.
    cors_origins: List[str] = ["http://localhost:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """
        Handles both a JSON array string from .env
        and an already-parsed list (e.g., during testing).
        """
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                # If it's a plain comma-separated string, split it
                return [origin.strip() for origin in v.split(",")]
        return v

    # ── Email ────────────────────────────────────────────────────
    email_provider: Literal["smtp", "sendgrid"] = "smtp"

    # SMTP settings
    smtp_host: str = "sandbox.smtp.mailtrap.io"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    email_from: str = "noreply@authshield.dev"
    email_from_name: str = "AuthShield"

    # SendGrid settings
    sendgrid_api_key: str = ""

    # ── Frontend URLs ─────────────────────────────────────────────
    frontend_url: str = "http://localhost:3000"
    verify_email_path: str = "/verify-email"
    reset_password_path: str = "/reset-password"

    # ── Google OAuth ─────────────────────────────────────────────
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""

    # ── GitHub OAuth ─────────────────────────────────────────────
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = ""

    # ── Rate Limiting ─────────────────────────────────────────────
    rate_limit_login_per_minute: int = 5
    rate_limit_register_per_minute: int = 3
    rate_limit_password_reset_per_hour: int = 3

    # ── Password Policy ───────────────────────────────────────────
    bcrypt_rounds: int = 12
    password_min_length: int = 8
    password_max_length: int = 128

    # ── 2FA ──────────────────────────────────────────────────────
    totp_issuer_name: str = "AuthShield"

    # ── Computed Properties ───────────────────────────────────────
    @property
    def verify_email_url(self) -> str:
        """Full URL for email verification links."""
        return f"{self.frontend_url}{self.verify_email_path}"

    @property
    def reset_password_url(self) -> str:
        """Full URL for password reset links."""
        return f"{self.frontend_url}{self.reset_password_path}"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @model_validator(mode="after")
    def validate_production_settings(self):
        """
        In production, enforce stricter requirements.
        Catches misconfigurations before they become security issues.
        """
        if self.is_production:
            if self.jwt_secret_key == "change-this-to-a-random-256-bit-hex-string-in-production":
                raise ValueError("You MUST set a real JWT_SECRET_KEY in production!")
            if self.debug:
                raise ValueError("DEBUG must be False in production!")
        return self


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.

    lru_cache means this function only runs ONCE per process.
    Every call after the first returns the same Settings object.
    This is safe because settings don't change at runtime.

    Usage:
        from app.config import get_settings
        settings = get_settings()
    """
    return Settings()


# Module-level convenience alias
# Most files can do: from app.config import settings
settings = get_settings()