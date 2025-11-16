"""
Security middleware and utilities for API protection.

Implements:
- Security headers (CSP, X-Frame-Options, etc.)
- Request ID tracking for audit trails
- File upload validation
- Input sanitization
- Rate limiting helpers
"""
from fastapi import Request, Response, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable, Optional
import uuid
import time
import logging
import hashlib
import magic
from pathlib import Path

logger = logging.getLogger(__name__)

# ===== Request ID Tracking =====

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Add unique request ID to all requests for audit trail and debugging.

    Sets X-Request-ID header on both request and response.
    """

    async def dispatch(self, request: Request, call_next: Callable):
        # Generate or use existing request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Add to request state for access in endpoints
        request.state.request_id = request_id

        # Log request start
        logger.info(
            f"Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "client": request.client.host if request.client else "unknown"
            }
        )

        # Process request
        start_time = time.time()
        try:
            response = await call_next(request)

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            # Log request completion
            duration = time.time() - start_time
            logger.info(
                f"Request completed",
                extra={
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "duration_seconds": round(duration, 3)
                }
            )

            return response

        except Exception as e:
            # Log error with request ID
            duration = time.time() - start_time
            logger.error(
                f"Request failed: {str(e)}",
                extra={
                    "request_id": request_id,
                    "duration_seconds": round(duration, 3),
                    "error": str(e)
                },
                exc_info=True
            )

            # Return error response with request ID
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal Server Error",
                    "detail": str(e),
                    "request_id": request_id
                },
                headers={"X-Request-ID": request_id}
            )


# ===== Security Headers Middleware =====

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add comprehensive security headers to all responses.

    Headers added:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security: HSTS for HTTPS
    - Content-Security-Policy: Restrictive CSP
    - Referrer-Policy: no-referrer-when-downgrade
    - Permissions-Policy: Restrict browser features
    """

    def __init__(self, app, enable_hsts: bool = False):
        super().__init__(app)
        self.enable_hsts = enable_hsts

    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Enable XSS filter
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content Security Policy
        # Restrictive CSP - adjust based on your UI needs
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",  # Adjust for React
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # Referrer policy
        response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"

        # Permissions policy (restrict browser features)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )

        # HSTS (only in production with HTTPS)
        if self.enable_hsts and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response


# ===== File Upload Validation =====

class FileValidator:
    """
    Validate uploaded files for security.

    Checks:
    - File size limits
    - MIME type validation
    - Extension whitelist
    - Content validation (magic bytes)
    - Malware patterns (basic)
    """

    # Allowed MIME types for telemetry files
    ALLOWED_MIME_TYPES = {
        "application/json",
        "application/x-ndjson",
        "application/jsonl",
        "text/plain",
        "application/octet-stream",  # For .jsonl without proper MIME
    }

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {".json", ".jsonl", ".txt", ".log"}

    # Maximum file size (100 MB default)
    MAX_FILE_SIZE = 100 * 1024 * 1024

    @classmethod
    async def validate_upload(
        cls,
        file: UploadFile,
        max_size: Optional[int] = None,
        allowed_extensions: Optional[set] = None
    ) -> dict:
        """
        Validate an uploaded file.

        Args:
            file: Uploaded file
            max_size: Maximum file size in bytes
            allowed_extensions: Set of allowed file extensions

        Returns:
            Validation result dict

        Raises:
            HTTPException: If validation fails
        """
        max_size = max_size or cls.MAX_FILE_SIZE
        allowed_extensions = allowed_extensions or cls.ALLOWED_EXTENSIONS

        # Check filename
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="Filename is required"
            )

        # Check file extension
        file_path = Path(file.filename)
        if file_path.suffix.lower() not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File extension not allowed. Allowed: {', '.join(allowed_extensions)}"
            )

        # Prevent path traversal
        if ".." in file.filename or "/" in file.filename or "\\" in file.filename:
            raise HTTPException(
                status_code=400,
                detail="Invalid filename - path traversal detected"
            )

        # Read file content for validation
        content = await file.read()
        file_size = len(content)

        # Reset file pointer
        await file.seek(0)

        # Check file size
        if file_size > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size: {max_size / 1024 / 1024:.1f} MB"
            )

        if file_size == 0:
            raise HTTPException(
                status_code=400,
                detail="File is empty"
            )

        # Validate MIME type using python-magic
        try:
            mime_type = magic.from_buffer(content[:2048], mime=True)

            # Be lenient with text files
            if not (mime_type in cls.ALLOWED_MIME_TYPES or mime_type.startswith("text/")):
                logger.warning(
                    f"Potentially invalid MIME type: {mime_type} for file {file.filename}"
                )
                # Don't block, just warn - JSONL files often have generic MIME types
        except Exception as e:
            logger.warning(f"MIME type detection failed: {e}")

        # Basic malware pattern detection
        suspicious_patterns = [
            b"<script",  # XSS
            b"javascript:",  # XSS
            b"<?php",  # PHP code
            b"<%",  # ASP code
            b"\x00",  # Null bytes
        ]

        content_lower = content[:4096].lower()
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                logger.warning(
                    f"Suspicious pattern detected in upload: {file.filename}"
                )
                raise HTTPException(
                    status_code=400,
                    detail="File contains suspicious content"
                )

        # Calculate file hash for audit trail
        file_hash = hashlib.sha256(content).hexdigest()

        return {
            "filename": file.filename,
            "size_bytes": file_size,
            "content_type": file.content_type,
            "detected_mime": mime_type if 'mime_type' in locals() else None,
            "sha256": file_hash,
            "validated": True
        }


# ===== Input Sanitization =====

def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Sanitize string input to prevent injection attacks.

    Args:
        value: Input string
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        return str(value)

    # Truncate to max length
    value = value[:max_length]

    # Remove null bytes
    value = value.replace("\x00", "")

    # Strip control characters except newlines and tabs
    value = "".join(
        char for char in value
        if char.isprintable() or char in ["\n", "\t", "\r"]
    )

    return value.strip()


def sanitize_path(path: str) -> str:
    """
    Sanitize file path to prevent path traversal.

    Args:
        path: Input path

    Returns:
        Sanitized path

    Raises:
        ValueError: If path is invalid
    """
    # Remove null bytes
    path = path.replace("\x00", "")

    # Check for path traversal
    if ".." in path:
        raise ValueError("Path traversal detected")

    # Convert to Path object and resolve
    try:
        safe_path = Path(path).resolve()
        return str(safe_path)
    except Exception as e:
        raise ValueError(f"Invalid path: {e}")


# ===== Rate Limit Helpers =====

def get_client_ip(request: Request) -> str:
    """
    Get client IP address from request.

    Handles X-Forwarded-For and X-Real-IP headers.

    Args:
        request: FastAPI request

    Returns:
        Client IP address
    """
    # Check X-Forwarded-For (from reverse proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take first IP in chain
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct client
    if request.client:
        return request.client.host

    return "unknown"


# ===== Audit Logging =====

class AuditLogger:
    """
    Audit logger for security-sensitive operations.

    Logs all file uploads, analysis requests, and configuration changes.
    """

    @staticmethod
    def log_file_upload(
        request_id: str,
        filename: str,
        size_bytes: int,
        client_ip: str,
        user: Optional[str] = None
    ):
        """Log file upload event."""
        logger.info(
            "File uploaded",
            extra={
                "event_type": "file_upload",
                "request_id": request_id,
                "filename": filename,
                "size_bytes": size_bytes,
                "client_ip": client_ip,
                "user": user or "anonymous"
            }
        )

    @staticmethod
    def log_analysis_request(
        request_id: str,
        event_count: int,
        client_ip: str,
        user: Optional[str] = None
    ):
        """Log analysis request event."""
        logger.info(
            "Analysis requested",
            extra={
                "event_type": "analysis_request",
                "request_id": request_id,
                "event_count": event_count,
                "client_ip": client_ip,
                "user": user or "anonymous"
            }
        )

    @staticmethod
    def log_scenario_generation(
        request_id: str,
        scenario_name: str,
        client_ip: str,
        user: Optional[str] = None
    ):
        """Log scenario generation event."""
        logger.info(
            "Scenario generated",
            extra={
                "event_type": "scenario_generation",
                "request_id": request_id,
                "scenario_name": scenario_name,
                "client_ip": client_ip,
                "user": user or "anonymous"
            }
        )

    @staticmethod
    def log_security_event(
        event_type: str,
        request_id: str,
        description: str,
        client_ip: str,
        severity: str = "WARNING"
    ):
        """Log security event."""
        log_func = getattr(logger, severity.lower(), logger.warning)
        log_func(
            f"Security event: {description}",
            extra={
                "event_type": f"security_{event_type}",
                "request_id": request_id,
                "client_ip": client_ip,
                "severity": severity
            }
        )
