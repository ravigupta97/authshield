"""

Security headers middleware.

HEADERS WE'RE ADDING AND WHY:

X-Content-Type-Options: nosniff
  Prevents browsers from MIME-sniffing responses away from the
  declared content-type. Stops attacks where a malicious file
  is uploaded and served with a wrong content type.

X-Frame-Options: DENY
  Prevents the app from being embedded in iframes.
  Blocks clickjacking attacks where an attacker overlays an
  invisible iframe on a legitimate-looking page.

X-XSS-Protection: 1; mode=block
  Enables the browser's built-in XSS filter.
  Deprecated in modern browsers (CSP is better) but still
  useful for older browsers.

Referrer-Policy: strict-origin-when-cross-origin
  Controls how much referrer info is included with requests.
  'strict-origin-when-cross-origin' sends origin only for
  cross-origin requests — no path/query string leakage.

Permissions-Policy
  Disables browser features our API doesn't need.
  Prevents malicious scripts from accessing camera,
  microphone, geolocation, etc. even if injected.

Strict-Transport-Security (HSTS)
  Only added in production. Tells browsers to always use HTTPS.
  'max-age=31536000' = remember for 1 year.
  'includeSubDomains' = apply to all subdomains.
  WARNING: Only enable after you have valid HTTPS configured.

Content-Security-Policy
  Only added in production. Restricts which resources can load.
  For an API server, we're very restrictive — API responses
  are JSON, not HTML, so CSP mostly protects the Swagger docs.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds security headers to every response.
    Applied at the middleware layer — affects ALL endpoints uniformly.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # ── Headers for all environments ──────────────────────────
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        # ── Remove headers that leak server info ──────────────────
        # 'Server' header reveals the web server software and version
        # Attackers use this to target known vulnerabilities
        if "server" in response.headers:
            del response.headers["server"]

        # ── Production-only headers ───────────────────────────────
        if settings.is_production:
            # HSTS: Force HTTPS for 1 year (only safe with valid cert)
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
            # CSP: Restrict resource loading for Swagger UI
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "img-src 'self' data: cdn.jsdelivr.net;"
            )

        return response