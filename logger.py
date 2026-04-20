"""
Structured logging for SNI-Spoofing proxy.
Provides DEBUG, INFO, WARNING, ERROR levels with timestamps and context.
"""

import logging
import sys
import threading
from datetime import datetime
from enum import IntEnum
from typing import Any, Optional


class LogLevel(IntEnum):
    """Log level enumeration matching verbose levels."""
    ERROR = 0
    WARNING = 1
    INFO = 2
    DEBUG = 3
    TRACE = 4


class StructuredLogger:
    """
    Structured logger with context-aware logging.
    Supports multiple verbosity levels and colored output.
    """
    
    # ANSI color codes
    COLORS = {
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "RED": "\033[91m",
        "GREEN": "\033[92m",
        "YELLOW": "\033[93m",
        "BLUE": "\033[94m",
        "MAGENTA": "\033[95m",
        "CYAN": "\033[96m",
        "GRAY": "\033[90m",
    }
    
    def __init__(self, name: str = "SNI-Spoofing", verbose: int = 0, log_file: Optional[str] = None):
        self.name = name
        self.verbose = min(verbose, 4)  # Cap at TRACE
        self._lock = threading.Lock()
        self._log_file = log_file
        self._file_handler: Optional[logging.FileHandler] = None
        
        # Statistics
        self._stats = {
            "total_connections": 0,
            "successful_connections": 0,
            "failed_connections": 0,
            "total_bytes_sent": 0,
            "total_bytes_received": 0,
            "total_retries": 0,
        }
        
        # Setup file handler if specified
        if self._log_file:
            try:
                self._file_handler = logging.FileHandler(self._log_file, encoding='utf-8')
                self._file_handler.setLevel(logging.DEBUG)
            except Exception as e:
                print(f"Failed to create log file: {e}")
    
    def _format_message(self, level: str, message: str, **kwargs) -> str:
        """Format message with optional context."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Build context string
        context_parts = []
        for key, value in kwargs.items():
            if value is not None:
                context_parts.append(f"{key}={value}")
        
        context_str = f" | {', '.join(context_parts)}" if context_parts else ""
        
        return f"{timestamp} [{level:8}] {message}{context_str}"
    
    def _should_log(self, level: LogLevel) -> bool:
        """Check if message should be logged based on verbosity."""
        return level <= self.verbose
    
    def _log(self, level: LogLevel, level_str: str, message: str, color: str = "", **kwargs):
        """Internal logging method."""
        if not self._should_log(level):
            return
        
        formatted = self._format_message(level_str, message, **kwargs)
        
        # Console output with color
        if color and sys.stdout.isatty():
            print(f"{color}{formatted}{self.COLORS['RESET']}")
        else:
            print(formatted)
        
        # File output
        if self._file_handler:
            try:
                self._file_handler.write(formatted + "\n")
            except Exception:
                pass
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log(LogLevel.DEBUG, "DEBUG", message, self.COLORS["GRAY"], **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log(LogLevel.INFO, "INFO", message, self.COLORS["CYAN"], **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log(LogLevel.WARNING, "WARNING", message, self.COLORS["YELLOW"], **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message."""
        self._log(LogLevel.ERROR, "ERROR", message, self.COLORS["RED"], **kwargs)
    
    def trace(self, message: str, **kwargs):
        """Log trace message (very verbose)."""
        self._log(LogLevel.TRACE, "TRACE", message, self.COLORS["GRAY"], **kwargs)
    
    # Specialized logging methods
    
    def log_connection(self, ip: str, sni: str, success: bool, latency: float = 0, **kwargs):
        """Log connection attempt."""
        status = "SUCCESS" if success else "FAILED"
        color = self.COLORS["GREEN"] if success else self.COLORS["RED"]
        
        if success:
            self.info(
                f"Connection {status}",
                ip=ip, sni=sni, latency=f"{latency:.2f}ms", **kwargs
            )
        else:
            self.warning(
                f"Connection {status}",
                ip=ip, sni=sni, **kwargs
            )
    
    def log_reconnect(self, ip: str, attempt: int, max_retries: int, **kwargs):
        """Log reconnection attempt."""
        self.info(
            f"Reconnecting (attempt {attempt}/{max_retries})",
            ip=ip, attempt=attempt, max=max_retries, **kwargs
        )
    
    def log_tls_handshake(self, ip: str, sni: str, success: bool, **kwargs):
        """Log TLS handshake result."""
        status = "SUCCESS" if success else "FAILED"
        if success:
            self.debug(f"TLS handshake {status}", ip=ip, sni=sni, **kwargs)
        else:
            self.warning(f"TLS handshake {status}", ip=ip, sni=sni, **kwargs)
    
    def log_data_transfer(self, direction: str, bytes_count: int, **kwargs):
        """Log data transfer."""
        self.trace(
            f"Data {direction}",
            bytes=bytes_count, **kwargs
        )
        with self._lock:
            if direction == "sent":
                self._stats["total_bytes_sent"] += bytes_count
            elif direction == "received":
                self._stats["total_bytes_received"] += bytes_count
    
    def log_ip_selection(self, ip: str, latency: float, reason: str = "fastest", **kwargs):
        """Log IP selection decision."""
        self.info(
            f"Selected IP: {ip} (latency: {latency:.2f}ms, reason: {reason})",
            **kwargs
        )
    
    def log_circuit_breaker(self, ip: str, action: str, **kwargs):
        """Log circuit breaker state change."""
        self.warning(
            f"Circuit breaker: {action}",
            ip=ip, **kwargs
        )
    
    def log_health_check(self, ip: str, healthy: bool, rtt: float = 0, **kwargs):
        """Log health check result."""
        status = "healthy" if healthy else "unhealthy"
        if healthy:
            self.debug(f"Health check: {ip} ({status}, RTT: {rtt:.2f}ms)", **kwargs)
        else:
            self.warning(f"Health check: {ip} ({status})", **kwargs)
    
    # Statistics methods
    
    def increment_connection(self, success: bool = True):
        """Increment connection counter."""
        with self._lock:
            self._stats["total_connections"] += 1
            if success:
                self._stats["successful_connections"] += 1
            else:
                self._stats["failed_connections"] += 1
    
    def increment_retries(self):
        """Increment retry counter."""
        with self._lock:
            self._stats["total_retries"] += 1
    
    def get_stats(self) -> dict:
        """Get current statistics."""
        with self._lock:
            stats = self._stats.copy()
            if stats["total_connections"] > 0:
                stats["success_rate"] = (
                    stats["successful_connections"] / stats["total_connections"] * 100
                )
            else:
                stats["success_rate"] = 0
            return stats
    
    def print_stats(self):
        """Print current statistics."""
        stats = self.get_stats()
        print("\n" + "=" * 50)
        print("Statistics:")
        print(f"  Total connections: {stats['total_connections']}")
        print(f"  Successful: {stats['successful_connections']}")
        print(f"  Failed: {stats['failed_connections']}")
        print(f"  Success rate: {stats['success_rate']:.1f}%")
        print(f"  Total retries: {stats['total_retries']}")
        print(f"  Bytes sent: {stats['total_bytes_sent']:,}")
        print(f"  Bytes received: {stats['total_bytes_received']:,}")
        print("=" * 50 + "\n")
    
    def close(self):
        """Close logger and file handler."""
        if self._file_handler:
            self._file_handler.close()


# Global logger instance
_logger: Optional[StructuredLogger] = None


def get_logger(name: str = "SNI-Spoofing", verbose: int = 0, log_file: Optional[str] = None) -> StructuredLogger:
    """Get or create the global logger instance."""
    global _logger
    if _logger is None:
        _logger = StructuredLogger(name, verbose, log_file)
    return _logger


def set_logger(logger: StructuredLogger):
    """Set the global logger instance."""
    global _logger
    _logger = logger