"""

Handles all email sending. Abstracts over SMTP and SendGrid
so switching providers requires no changes elsewhere.
"""

import aiosmtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import structlog

from app.config import settings

log = structlog.get_logger()


class EmailService:
    """
    Sends transactional emails (verification, password reset, etc.)
    All methods are async — email sending never blocks the event loop.
    """

    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
    ) -> bool:
        """
        Send an email using the configured provider.
        Returns True on success, False on failure.
        NEVER raises — email failure shouldn't break the main flow.
        """
        try:
            if settings.email_provider == "smtp":
                return await self._send_via_smtp(
                    to_email, subject, html_body, text_body
                )
            elif settings.email_provider == "sendgrid":
                return await self._send_via_sendgrid(
                    to_email, subject, html_body, text_body
                )
            else:
                log.error("Unknown email provider", provider=settings.email_provider)
                return False
        except Exception as e:
            log.error("Failed to send email", error=str(e), to=to_email)
            return False

    async def _send_via_smtp(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
    ) -> bool:
        """Send via SMTP (Mailtrap for dev, any SMTP server for prod)."""
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{settings.email_from_name} <{settings.email_from}>"
        message["To"] = to_email

        # Attach both plain text and HTML versions.
        # Email clients pick the best one they can render.
        message.attach(MIMEText(text_body, "plain"))
        message.attach(MIMEText(html_body, "html"))

        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            use_tls=False,
            start_tls=settings.smtp_use_tls,
        )

        log.info("Email sent via SMTP", to=to_email, subject=subject)
        return True

    async def _send_via_sendgrid(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
    ) -> bool:
        """Send via SendGrid API."""
        import httpx

        payload = {
            "personalizations": [{"to": [{"email": to_email}]}],
            "from": {
                "email": settings.email_from,
                "name": settings.email_from_name,
            },
            "subject": subject,
            "content": [
                {"type": "text/plain", "value": text_body},
                {"type": "text/html", "value": html_body},
            ],
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.sendgrid.com/v3/mail/send",
                json=payload,
                headers={"Authorization": f"Bearer {settings.sendgrid_api_key}"},
            )
            response.raise_for_status()

        log.info("Email sent via SendGrid", to=to_email, subject=subject)
        return True

    # ── Email Templates ───────────────────────────────────────────

    async def send_verification_email(
        self,
        to_email: str,
        full_name: str,
        token: str,
    ) -> bool:
        """Send the email verification link after registration."""
        verification_url = f"{settings.verify_email_url}?token={token}"

        subject = f"Verify your {settings.app_name} account"

        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Welcome to {settings.app_name}, {full_name}!</h2>
            <p>Thank you for registering. Please verify your email address
               to activate your account.</p>
            <p>
                <a href="{verification_url}"
                   style="background-color: #4F46E5; color: white;
                          padding: 12px 24px; text-decoration: none;
                          border-radius: 4px; display: inline-block;">
                    Verify Email Address
                </a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="color: #6B7280; word-break: break-all;">{verification_url}</p>
            <p style="color: #6B7280; font-size: 14px;">
                This link expires in 24 hours. If you didn't create an account,
                you can safely ignore this email.
            </p>
        </div>
        """

        text_body = f"""
        Welcome to {settings.app_name}, {full_name}!

        Please verify your email address by clicking the link below:
        {verification_url}

        This link expires in 24 hours.
        If you didn't create an account, ignore this email.
        """

        return await self.send_email(to_email, subject, html_body, text_body)

    async def send_password_reset_email(
        self,
        to_email: str,
        full_name: str,
        token: str,
    ) -> bool:
        """Send password reset link."""
        reset_url = f"{settings.reset_password_url}?token={token}"
        subject = f"Reset your {settings.app_name} password"

        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Password Reset Request</h2>
            <p>Hi {full_name},</p>
            <p>We received a request to reset your password.</p>
            <p>
                <a href="{reset_url}"
                   style="background-color: #4F46E5; color: white;
                          padding: 12px 24px; text-decoration: none;
                          border-radius: 4px; display: inline-block;">
                    Reset Password
                </a>
            </p>
            <p>Or copy and paste: <span style="color: #6B7280;">{reset_url}</span></p>
            <p style="color: #6B7280; font-size: 14px;">
                This link expires in 1 hour. If you didn't request this,
                your password has not been changed.
            </p>
        </div>
        """

        text_body = f"""
        Hi {full_name},

        Reset your password here: {reset_url}

        This link expires in 1 hour.
        If you didn't request this, ignore this email.
        """

        return await self.send_email(to_email, subject, html_body, text_body)


# Module-level instance — import and use directly in services
email_service = EmailService()