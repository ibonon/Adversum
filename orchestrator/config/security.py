from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from ..config.settings import settings

api_key_header = APIKeyHeader(name=settings.API_KEY_HEADER_NAME, auto_error=False)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    """
    Validates the API Key from the header.
    Raises 403 if invalid or missing.
    """
    if api_key_header == settings.API_KEY_SECRET:
        return api_key_header
    
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials"
    )
