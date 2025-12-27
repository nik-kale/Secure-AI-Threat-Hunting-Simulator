"""
API Authentication and Authorization with brute force protection.
"""
from fastapi import Security, HTTPException, status, Request
from fastapi.security import APIKeyHeader
import os
import logging
import time
from collections import defaultdict
from typing import Dict, List
from analysis_engine.api.security import get_client_ip, AuditLogger

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Brute force protection configuration
LOCKOUT_THRESHOLD = int(os.getenv("API_KEY_LOCKOUT_THRESHOLD", "10"))
LOCKOUT_DURATION = int(os.getenv("API_KEY_LOCKOUT_DURATION", "900"))  # 15 minutes
ATTEMPT_WINDOW = int(os.getenv("API_KEY_ATTEMPT_WINDOW", "300"))  # 5 minutes
ENABLE_BRUTE_FORCE_PROTECTION = os.getenv("ENABLE_BRUTE_FORCE_PROTECTION", "true").lower() == "true"

# Track failed attempts per IP (timestamp list)
failed_attempts: Dict[str, List[float]] = defaultdict(list)
locked_ips: Dict[str, float] = {}  # IP -> unlock_time


async def verify_api_key(request: Request, api_key: str = Security(api_key_header)) -> str | None:
    """
    Verify API key with brute force protection.

    In development mode (no API_KEY env var), allows all requests.
    In production mode, requires valid API key and enforces brute force protection.

    Args:
        request: FastAPI request object (for IP extraction)
        api_key: API key from X-API-Key header

    Returns:
        API key if valid, None if in development mode

    Raises:
        HTTPException: If API key is invalid, missing, or IP is locked out
    """
    client_ip = get_client_ip(request)
    expected_key = os.getenv("API_KEY")

    # Development mode - no API key required
    if not expected_key:
        logger.debug("API key not configured - running in development mode")
        return None

    # Check if IP is locked out (brute force protection)
    if ENABLE_BRUTE_FORCE_PROTECTION:
        if client_ip in locked_ips:
            if time.time() < locked_ips[client_ip]:
                remaining = int(locked_ips[client_ip] - time.time())
                logger.warning(f"Blocked request from locked IP: {client_ip} (remaining: {remaining}s)")
                
                AuditLogger.log_security_event(
                    "blocked_locked_ip",
                    request_id=getattr(request.state, 'request_id', 'unknown'),
                    description=f"Blocked request from locked IP: {client_ip}",
                    client_ip=client_ip,
                    severity="WARNING",
                    metadata={"remaining_seconds": remaining}
                )
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many failed authentication attempts. Try again in {remaining} seconds.",
                    headers={"Retry-After": str(remaining)}
                )
            else:
                # Lockout expired, remove from locked list
                del locked_ips[client_ip]
                logger.info(f"IP lockout expired for {client_ip}")

    # Production mode - API key required
    if not api_key:
        logger.warning(f"Missing API key from {client_ip}")
        _record_failed_attempt(request, client_ip, "missing_api_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key != expected_key:
        logger.warning(f"Invalid API key attempted from {client_ip}")
        _record_failed_attempt(request, client_ip, "invalid_api_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Valid API key - clear failed attempts for this IP
    if ENABLE_BRUTE_FORCE_PROTECTION and client_ip in failed_attempts:
        del failed_attempts[client_ip]
        logger.debug(f"Cleared failed attempts for {client_ip}")

    return api_key


def _record_failed_attempt(request: Request, ip: str, reason: str):
    """
    Record a failed authentication attempt and enforce lockout if threshold exceeded.
    
    Args:
        request: FastAPI request object
        ip: Client IP address
        reason: Reason for failure (missing_api_key, invalid_api_key)
    """
    if not ENABLE_BRUTE_FORCE_PROTECTION:
        return
    
    now = time.time()
    
    # Clean old attempts outside window
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < ATTEMPT_WINDOW]
    
    # Add current attempt
    failed_attempts[ip].append(now)
    
    attempt_count = len(failed_attempts[ip])
    
    # Log security event
    AuditLogger.log_security_event(
        "failed_authentication",
        request_id=getattr(request.state, 'request_id', 'unknown'),
        description=f"Failed authentication attempt ({reason})",
        client_ip=ip,
        severity="WARNING",
        metadata={
            "reason": reason,
            "attempt_count": attempt_count,
            "window_seconds": ATTEMPT_WINDOW
        }
    )
    
    # Check if threshold exceeded
    if attempt_count >= LOCKOUT_THRESHOLD:
        locked_ips[ip] = now + LOCKOUT_DURATION
        
        logger.error(
            f"IP {ip} locked out after {attempt_count} failed attempts. "
            f"Lockout duration: {LOCKOUT_DURATION}s"
        )
        
        AuditLogger.log_security_event(
            "ip_lockout",
            request_id=getattr(request.state, 'request_id', 'unknown'),
            description=f"IP locked out after {attempt_count} failed attempts",
            client_ip=ip,
            severity="CRITICAL",
            metadata={
                "attempt_count": attempt_count,
                "lockout_duration": LOCKOUT_DURATION,
                "unlock_time": locked_ips[ip]
            }
        )


def get_lockout_status(ip: str) -> Dict:
    """
    Get lockout status for an IP address.
    
    Args:
        ip: IP address to check
        
    Returns:
        Dictionary with lockout information
    """
    now = time.time()
    
    is_locked = ip in locked_ips and now < locked_ips[ip]
    remaining = int(locked_ips[ip] - now) if is_locked else 0
    
    # Clean old failed attempts
    recent_attempts = [t for t in failed_attempts.get(ip, []) if now - t < ATTEMPT_WINDOW]
    
    return {
        "ip": ip,
        "is_locked": is_locked,
        "remaining_seconds": remaining,
        "recent_attempts": len(recent_attempts),
        "threshold": LOCKOUT_THRESHOLD,
        "enabled": ENABLE_BRUTE_FORCE_PROTECTION
    }


def clear_lockout(ip: str) -> bool:
    """
    Manually clear lockout for an IP (admin function).
    
    Args:
        ip: IP address to unlock
        
    Returns:
        True if lockout was cleared, False if not locked
    """
    if ip in locked_ips:
        del locked_ips[ip]
        if ip in failed_attempts:
            del failed_attempts[ip]
        logger.info(f"Manual lockout clearance for IP: {ip}")
        return True
    return False


def get_all_locked_ips() -> List[Dict]:
    """
    Get list of all locked IPs (admin function).
    
    Returns:
        List of dictionaries with locked IP information
    """
    now = time.time()
    result = []
    
    for ip, unlock_time in locked_ips.items():
        if now < unlock_time:
            result.append({
                "ip": ip,
                "remaining_seconds": int(unlock_time - now),
                "unlock_time": unlock_time,
                "failed_attempts": len(failed_attempts.get(ip, []))
            })
    
    return result


async def verify_admin_key(request: Request, api_key: str = Security(api_key_header)) -> str:
    """
    Verify admin-level API key for sensitive operations.

    Args:
        request: FastAPI request object
        api_key: API key from X-API-Key header

    Returns:
        API key if valid admin key

    Raises:
        HTTPException: If not a valid admin key
    """
    admin_key = os.getenv("ADMIN_API_KEY")

    if not admin_key:
        # If no admin key set, fall back to regular API key check
        return await verify_api_key(request, api_key)

    if api_key != admin_key:
        logger.warning(f"Non-admin key used for admin endpoint from {get_client_ip(request)}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return api_key
