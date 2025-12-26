"""
Timeout middleware for FastAPI to prevent long-running requests.
"""
import asyncio
import logging
import time
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


logger = logging.getLogger(__name__)


class TimeoutMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce request timeouts.
    
    Prevents requests from hanging indefinitely by enforcing a maximum
    execution time. Returns 504 Gateway Timeout if exceeded.
    
    Example:
        from fastapi import FastAPI
        
        app = FastAPI()
        app.add_middleware(TimeoutMiddleware, timeout_seconds=300)
    """
    
    def __init__(
        self,
        app,
        timeout_seconds: int = 300,
        exclude_paths: list[str] = None
    ):
        """
        Initialize timeout middleware.
        
        Args:
            app: FastAPI application
            timeout_seconds: Maximum request duration in seconds (default: 5 minutes)
            exclude_paths: List of paths to exclude from timeout (e.g., ["/ws", "/stream"])
        """
        super().__init__(app)
        self.timeout = timeout_seconds
        self.exclude_paths = exclude_paths or []
        
        logger.info(f"Timeout middleware initialized: {timeout_seconds}s timeout")
    
    async def dispatch(self, request: Request, call_next: Callable):
        """
        Process request with timeout enforcement.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Response or timeout error
        """
        # Skip timeout for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)
        
        start_time = time.time()
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        try:
            # Execute request with timeout
            response = await asyncio.wait_for(
                call_next(request),
                timeout=self.timeout
            )
            
            # Log slow requests (>10s)
            duration = time.time() - start_time
            if duration > 10:
                logger.warning(
                    f"Slow request: {request.method} {request.url.path} "
                    f"took {duration:.2f}s (request_id: {request_id})"
                )
            
            return response
        
        except asyncio.TimeoutError:
            duration = time.time() - start_time
            logger.error(
                f"Request timeout: {request.method} {request.url.path} "
                f"exceeded {self.timeout}s (request_id: {request_id})"
            )
            
            return JSONResponse(
                status_code=504,
                content={
                    "error": "Request timeout",
                    "message": f"Request exceeded maximum duration of {self.timeout} seconds",
                    "timeout_seconds": self.timeout,
                    "request_id": request_id
                }
            )
        
        except Exception as e:
            # Re-raise other exceptions
            logger.error(f"Request failed: {e} (request_id: {request_id})")
            raise

