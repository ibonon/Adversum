from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from ..config.settings import settings

class LimitUploadSize(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            content_length = request.headers.get("content-length")
            if content_length:
                if int(content_length) > settings.MAX_BODY_SIZE:
                    raise HTTPException(status_code=413, detail="Request entity too large")
        
        return await call_next(request)
