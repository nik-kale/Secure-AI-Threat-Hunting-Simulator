"""
Circuit breaker pattern implementation for fault tolerance.
"""
import time
import asyncio
import logging
from enum import Enum
from typing import Callable, Optional, Any, TypeVar, ParamSpec
from functools import wraps
from dataclasses import dataclass
from datetime import datetime, timedelta


logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""
    pass


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker monitoring."""
    state: CircuitState
    failure_count: int
    success_count: int
    last_failure_time: Optional[datetime]
    last_state_change: datetime
    total_calls: int
    rejected_calls: int


P = ParamSpec('P')
T = TypeVar('T')


class CircuitBreaker:
    """
    Circuit breaker for preventing cascading failures.
    
    States:
    - CLOSED: Normal operation, failures are counted
    - OPEN: Too many failures, requests are rejected immediately
    - HALF_OPEN: After recovery timeout, testing if service recovered
    
    Example:
        breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        
        @breaker.protect
        async def call_external_api():
            return await api_client.get("/data")
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 2,
        timeout: float = 30.0,
        name: str = "unnamed"
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery (HALF_OPEN)
            success_threshold: Number of successes in HALF_OPEN needed to close
            timeout: Request timeout in seconds
            name: Name of the circuit for logging
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.name = name
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._last_state_change = time.time()
        self._total_calls = 0
        self._rejected_calls = 0
        
        logger.info(
            f"Circuit breaker '{self.name}' initialized: "
            f"threshold={failure_threshold}, recovery={recovery_timeout}s"
        )
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state (with automatic recovery check)."""
        if self._state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._transition_to_half_open()
        return self._state
    
    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self.state == CircuitState.CLOSED
    
    @property
    def is_open(self) -> bool:
        """Check if circuit is open (rejecting requests)."""
        return self.state == CircuitState.OPEN
    
    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing recovery)."""
        return self.state == CircuitState.HALF_OPEN
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt recovery."""
        if self._last_failure_time is None:
            return False
        return (time.time() - self._last_failure_time) >= self.recovery_timeout
    
    def _transition_to_half_open(self):
        """Transition to HALF_OPEN state."""
        logger.info(f"Circuit breaker '{self.name}' transitioning to HALF_OPEN")
        self._state = CircuitState.HALF_OPEN
        self._success_count = 0
        self._last_state_change = time.time()
    
    def _transition_to_open(self):
        """Transition to OPEN state."""
        logger.warning(
            f"Circuit breaker '{self.name}' OPEN: "
            f"{self._failure_count} failures exceeded threshold {self.failure_threshold}"
        )
        self._state = CircuitState.OPEN
        self._last_failure_time = time.time()
        self._last_state_change = time.time()
    
    def _transition_to_closed(self):
        """Transition to CLOSED state."""
        logger.info(f"Circuit breaker '{self.name}' transitioning to CLOSED")
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_state_change = time.time()
    
    def _record_success(self):
        """Record a successful call."""
        self._total_calls += 1
        
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                self._transition_to_closed()
        elif self._state == CircuitState.CLOSED:
            # Reset failure count on success
            self._failure_count = 0
    
    def _record_failure(self):
        """Record a failed call."""
        self._total_calls += 1
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._state == CircuitState.HALF_OPEN:
            # Any failure in HALF_OPEN immediately opens circuit
            self._transition_to_open()
        elif self._state == CircuitState.CLOSED:
            if self._failure_count >= self.failure_threshold:
                self._transition_to_open()
    
    def protect(self, func: Callable[P, T]) -> Callable[P, T]:
        """
        Decorator to protect a function with circuit breaker.
        
        Args:
            func: Function to protect (sync or async)
            
        Returns:
            Protected function
        """
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                return await self._call_async(func, *args, **kwargs)
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                return self._call_sync(func, *args, **kwargs)
            return sync_wrapper
    
    async def _call_async(self, func: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        """Execute async function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            self._rejected_calls += 1
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' is OPEN. "
                f"Service unavailable. Will retry after {self.recovery_timeout}s"
            )
        
        try:
            # Execute with timeout
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=self.timeout
            )
            self._record_success()
            return result
        
        except asyncio.TimeoutError:
            logger.error(f"Circuit breaker '{self.name}': Request timeout ({self.timeout}s)")
            self._record_failure()
            raise
        
        except Exception as e:
            logger.error(f"Circuit breaker '{self.name}': Request failed: {e}")
            self._record_failure()
            raise
    
    def _call_sync(self, func: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        """Execute sync function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            self._rejected_calls += 1
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' is OPEN. "
                f"Service unavailable. Will retry after {self.recovery_timeout}s"
            )
        
        try:
            result = func(*args, **kwargs)
            self._record_success()
            return result
        
        except Exception as e:
            logger.error(f"Circuit breaker '{self.name}': Request failed: {e}")
            self._record_failure()
            raise
    
    def get_stats(self) -> CircuitBreakerStats:
        """Get circuit breaker statistics."""
        return CircuitBreakerStats(
            state=self.state,
            failure_count=self._failure_count,
            success_count=self._success_count,
            last_failure_time=datetime.fromtimestamp(self._last_failure_time) if self._last_failure_time else None,
            last_state_change=datetime.fromtimestamp(self._last_state_change),
            total_calls=self._total_calls,
            rejected_calls=self._rejected_calls
        )
    
    def reset(self):
        """Manually reset circuit breaker to CLOSED state."""
        logger.info(f"Circuit breaker '{self.name}' manually reset")
        self._transition_to_closed()


# Global circuit breakers registry
_circuit_breakers: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    recovery_timeout: int = 60,
    **kwargs
) -> CircuitBreaker:
    """
    Get or create a circuit breaker instance.
    
    Args:
        name: Unique name for the circuit breaker
        failure_threshold: Number of failures before opening
        recovery_timeout: Seconds before attempting recovery
        **kwargs: Additional CircuitBreaker arguments
        
    Returns:
        CircuitBreaker instance
    """
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(
            name=name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            **kwargs
        )
    return _circuit_breakers[name]


def get_all_circuit_breakers() -> dict[str, CircuitBreaker]:
    """Get all registered circuit breakers."""
    return _circuit_breakers.copy()

