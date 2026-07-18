from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

class SecureHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # HSTS (Strict-Transport-Security)
        # Force HTTPS for 1 year, include subdomains
        # (Commented out for initial Dev loop on localhost HTTP, uncomment for Prod)
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS Protection (Legacy browsers, mostly handled by CSP now but good to have)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Content Security Policy (API doesn't serve HTML, but good hygiene)
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
        
        # Referrer Policy (Privacy)
        response.headers["Referrer-Policy"] = "no-referrer"
        
        return response
