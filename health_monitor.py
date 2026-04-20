"""
Health Monitor for periodic connection health checks.
Implements background monitoring, auto-recovery, and metrics collection.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable


@dataclass
class HealthMetrics:
    """Health check metrics."""
    timestamp: float = field(default_factory=time.time)
    rtt: float = 0
    is_healthy: bool = True
    error: str = ""


class HealthMonitor:
    """
    Background health monitor for connections.
    
    Features:
    - Periodic health checks
    - Connection health tracking
    - Auto-recovery triggers
    - RTT measurement
    - Metrics collection
    """
    
    def __init__(
        self,
        check_interval: int = 30,
        timeout: int = 5,
        max_consecutive_failures: int = 3,
        on_unhealthy: Optional[Callable[[], Awaitable]] = None,
        on_recovered: Optional[Callable[[], Awaitable]] = None,
        logger=None,
    ):
        self.check_interval = check_interval
        self.timeout = timeout
        self.max_consecutive_failures = max_consecutive_failures
        self.on_unhealthy = on_unhealthy
        self.on_recovered = on_recovered
        self.logger = logger
        
        # State
        self._is_running = False
        self._task: Optional[asyncio.Task] = None
        self._consecutive_failures = 0
        self._last_check_time = 0
        self._last_rtt = 0
        self._is_healthy = True
        
        # Metrics history
        self._metrics_history: list[HealthMetrics] = []
        self._max_history = 100
    
    async def start(self):
        """Start the health monitor."""
        if self._is_running:
            return
        
        self._is_running = True
        self._task = asyncio.create_task(self._run_loop())
        
        if self.logger:
            self.logger.info("Health monitor started", interval=self.check_interval)
    
    async def stop(self):
        """Stop the health monitor."""
        self._is_running = False
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        if self.logger:
            self.logger.info("Health monitor stopped")
    
    async def _run_loop(self):
        """Main health check loop."""
        while self._is_running:
            try:
                await self._check_health()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Health check error: {e}")
                await asyncio.sleep(5)  # Shorter interval on error
    
    async def _check_health(self):
        """Perform health check."""
        self._last_check_time = time.time()
        
        # This should be overridden or set via set_check_function
        rtt = await self._perform_check()
        
        self._last_rtt = rtt
        
        # Record metrics
        metric = HealthMetrics(
            timestamp=self._last_check_time,
            rtt=rtt,
            is_healthy=rtt < self.timeout * 1000,
        )
        self._add_metric(metric)
        
        if rtt < self.timeout * 1000:
            # Health check passed
            if not self._is_healthy:
                self._is_healthy = True
                self._consecutive_failures = 0
                if self.on_recovered:
                    await self.on_recovered()
                if self.logger:
                    self.logger.info("Connection recovered", rtt=f"{rtt:.2f}ms")
            else:
                if self.logger:
                    self.logger.log_health_check("main", True, rtt)
        else:
            # Health check failed
            self._consecutive_failures += 1
            
            if self.logger:
                self.logger.log_health_check("main", False, rtt)
            
            if self._consecutive_failures >= self.max_consecutive_failures:
                if self._is_healthy:
                    self._is_healthy = False
                    if self.on_unhealthy:
                        await self.on_unhealthy()
                    if self.logger:
                        self.logger.warning(
                            "Connection unhealthy, triggering recovery",
                            failures=self._consecutive_failures
                        )
    
    async def _perform_check(self) -> float:
        """
        Perform the actual health check.
        Override this method or set a custom check function.
        """
        # Default: just return success (override in subclass)
        return 0
    
    def set_check_function(self, func: Callable[[], Awaitable[float]]):
        """Set custom health check function."""
        self._perform_check = func
    
    def _add_metric(self, metric: HealthMetrics):
        """Add metric to history."""
        self._metrics_history.append(metric)
        if len(self._metrics_history) > self._max_history:
            self._metrics_history.pop(0)
    
    def is_healthy(self) -> bool:
        """Check if connection is healthy."""
        return self._is_healthy
    
    def get_last_rtt(self) -> float:
        """Get last measured RTT."""
        return self._last_rtt
    
    def get_metrics_summary(self) -> dict:
        """Get summary of health metrics."""
        if not self._metrics_history:
            return {
                "is_healthy": self._is_healthy,
                "checks": 0,
                "avg_rtt": 0,
                "min_rtt": 0,
                "max_rtt": 0,
            }
        
        rtts = [m.rtt for m in self._metrics_history if m.rtt > 0]
        
        return {
            "is_healthy": self._is_healthy,
            "checks": len(self._metrics_history),
            "avg_rtt": sum(rtts) / len(rtts) if rtts else 0,
            "min_rtt": min(rtts) if rtts else 0,
            "max_rtt": max(rtts) if rtts else 0,
            "consecutive_failures": self._consecutive_failures,
            "last_check": self._last_check_time,
        }


class PoolHealthMonitor(HealthMonitor):
    """
    Health monitor specifically for connection pool.
    Monitors all connections in the pool and triggers recovery.
    """
    
    def __init__(
        self,
        connection_pool,
        check_interval: int = 30,
        timeout: int = 5,
        max_consecutive_failures: int = 3,
        logger=None,
    ):
        super().__init__(
            check_interval=check_interval,
            timeout=timeout,
            max_consecutive_failures=max_consecutive_failures,
            logger=logger,
        )
        self._pool = connection_pool
    
    async def _perform_check(self) -> float:
        """Check health of connection pool."""
        start = time.perf_counter()
        
        try:
            health_results = await self._pool.health_check()
            
            # Calculate health ratio
            total = len(health_results)
            healthy = sum(1 for v in health_results.values() if v)
            
            if total == 0:
                # No connections - try to create one
                return float('inf')
            
            if healthy == 0:
                return float('inf')
            
            rtt = (time.perf_counter() - start) * 1000
            
            # Return RTT (health check passed)
            return rtt
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Pool health check failed: {e}")
            return float('inf')


class IPHealthMonitor(HealthMonitor):
    """
    Health monitor for IP manager.
    Tests connectivity to current IP and rotates if needed.
    """
    
    def __init__(
        self,
        ip_manager,
        check_interval: int = 30,
        timeout: int = 5,
        max_consecutive_failures: int = 3,
        logger=None,
    ):
        super().__init__(
            check_interval=check_interval,
            timeout=timeout,
            max_consecutive_failures=max_consecutive_failures,
            logger=logger,
        )
        self._ip_manager = ip_manager
    
    async def _perform_check(self) -> float:
        """Check health of current IP."""
        # Get current IP from manager
        working_ips = self._ip_manager.get_working_ips()
        
        if not working_ips:
            return float('inf')
        
        # Test the best working IP
        best_ip = working_ips[0]
        
        try:
            import asyncio
            start = time.perf_counter()
            
            # Simple TCP connect test
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(best_ip.ip, best_ip.port),
                timeout=self.timeout
            )
            
            rtt = (time.perf_counter() - start) * 1000
            
            writer.close()
            await writer.wait_closed()
            
            return rtt
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"IP health check failed: {best_ip.ip}, {e}")
            return float('inf')


class MetricsCollector:
    """
    Collects and aggregates metrics from various sources.
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        
        # Connection metrics
        self._connection_stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "retries": 0,
        }
        
        # Data transfer metrics
        self._transfer_stats = {
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets_sent": 0,
            "packets_received": 0,
        }
        
        # Timing metrics
        self._timing_stats = {
            "total_uptime": 0,
            "start_time": time.time(),
            "avg_connect_time": 0,
            "min_connect_time": float('inf'),
            "max_connect_time": 0,
            "connect_times": [],
        }
        
        self._lock = asyncio.Lock()
    
    async def record_connection(self, success: bool, connect_time: float = 0):
        """Record connection attempt."""
        async with self._lock:
            self._connection_stats["total"] += 1
            if success:
                self._connection_stats["success"] += 1
                
                # Update connect time stats
                if connect_time > 0:
                    self._timing_stats["connect_times"].append(connect_time)
                    if len(self._timing_stats["connect_times"]) > 100:
                        self._timing_stats["connect_times"].pop(0)
                    
                    times = self._timing_stats["connect_times"]
                    self._timing_stats["avg_connect_time"] = sum(times) / len(times)
                    self._timing_stats["min_connect_time"] = min(
                        self._timing_stats["min_connect_time"], connect_time
                    )
                    self._timing_stats["max_connect_time"] = max(
                        self._timing_stats["max_connect_time"], connect_time
                    )
            else:
                self._connection_stats["failed"] += 1
    
    async def record_retry(self):
        """Record retry attempt."""
        async with self._lock:
            self._connection_stats["retries"] += 1
    
    async def record_transfer(self, direction: str, bytes_count: int):
        """Record data transfer."""
        async with self._lock:
            if direction == "sent":
                self._transfer_stats["bytes_sent"] += bytes_count
                self._transfer_stats["packets_sent"] += 1
            elif direction == "received":
                self._transfer_stats["bytes_received"] += bytes_count
                self._transfer_stats["packets_received"] += 1
    
    def get_summary(self) -> dict:
        """Get metrics summary."""
        uptime = time.time() - self._timing_stats["start_time"]
        
        success_rate = 0
        if self._connection_stats["total"] > 0:
            success_rate = (
                self._connection_stats["success"] / self._connection_stats["total"] * 100
            )
        
        return {
            "connections": {
                **self._connection_stats,
                "success_rate": success_rate,
            },
            "transfer": self._transfer_stats,
            "timing": {
                **self._timing_stats,
                "uptime": uptime,
            },
        }
    
    async def print_summary(self):
        """Print metrics summary."""
        summary = self.get_summary()
        
        print("\n" + "=" * 60)
        print("METRICS SUMMARY")
        print("=" * 60)
        
        print("\nConnections:")
        c = summary["connections"]
        print(f"  Total: {c['total']}")
        print(f"  Success: {c['success']}")
        print(f"  Failed: {c['failed']}")
        print(f"  Retries: {c['retries']}")
        print(f"  Success Rate: {c['success_rate']:.1f}%")
        
        print("\nTransfer:")
        t = summary["transfer"]
        print(f"  Bytes Sent: {t['bytes_sent']:,}")
        print(f"  Bytes Received: {t['bytes_received']:,}")
        print(f"  Packets Sent: {t['packets_sent']:,}")
        print(f"  Packets Received: {t['packets_received']:,}")
        
        print("\nTiming:")
        ti = summary["timing"]
        print(f"  Uptime: {ti['uptime']:.1f}s")
        print(f"  Avg Connect Time: {ti['avg_connect_time']:.2f}ms")
        print(f"  Min Connect Time: {ti['min_connect_time']:.2f}ms" 
              if ti['min_connect_time'] != float('inf') else "  Min Connect Time: N/A")
        print(f"  Max Connect Time: {ti['max_connect_time']:.2f}ms"
              if ti['max_connect_time'] > 0 else "  Max Connect Time: N/A")
        
        print("=" * 60 + "\n")