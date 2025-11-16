"""
API Authentication and Authorization.
"""
from fastapi import Security, HTTPException, status, Request
from fastapi.security import APIKeyHeader
import os
import logging

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)) -> str | None:
    """
    Verify API key if configured.

    In development mode (no API_KEY env var), allows all requests.
    In production mode, requires valid API key.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        API key if valid, None if in development mode

    Raises:
        HTTPException: If API key is invalid or missing in production mode
    """
    expected_key = os.getenv("API_KEY")

    # Development mode - no API key required
    if not expected_key:
        logger.debug("API key not configured - running in development mode")
        return None

    # Production mode - API key required
    if not api_key:
        logger.warning("Missing API key in production mode")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key != expected_key:
        logger.warning(f"Invalid API key attempted")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key


async def verify_admin_key(api_key: str = Security(api_key_header)) -> str:
    """
    Verify admin-level API key for sensitive operations.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        API key if valid admin key

    Raises:
        HTTPException: If not a valid admin key
    """
    admin_key = os.getenv("ADMIN_API_KEY")

    if not admin_key:
        # If no admin key set, fall back to regular API key check
        return await verify_api_key(api_key)

    if api_key != admin_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return api_key
