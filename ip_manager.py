"""
Cloudflare IP Manager with intelligent selection, caching, and circuit breaker.
Manages a pool of Cloudflare IPs with latency testing and automatic rotation.
"""

import asyncio
import ipaddress
import random
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from collections import deque


@dataclass
class CloudflareIP:
    """Represents a Cloudflare IP with metadata."""
    ip: str
    port: int = 443
    latency: float = float('inf')
    success_count: int = 0
    failure_count: int = 0
    last_success: float = 0
    last_failure: float = 0
    is_healthy: bool = True
    is_circuit_open: bool = False
    circuit_open_time: float = 0
    
    def success(self):
        """Record successful connection."""
        self.success_count += 1
        self.last_success = time.time()
        self.is_healthy = True
        self.is_circuit_open = False
    
    def failure(self):
        """Record failed connection."""
        self.failure_count += 1
        self.last_failure = time.time()
    
    def mark_unhealthy(self):
        """Mark IP as unhealthy (circuit breaker)."""
        self.is_healthy = False
        self.is_circuit_open = True
        self.circuit_open_time = time.time()
    
    def should_try(self, cooldown: int = 300) -> bool:
        """Check if IP should be tried (circuit breaker logic)."""
        if not self.is_circuit_open:
            return True
        # Check if cooldown has passed
        return (time.time() - self.circuit_open_time) > cooldown


class IPManager:
    """
    Manages Cloudflare IPs with intelligent selection.
    
    Features:
    - Parallel latency testing
    - Automatic IP rotation on failure
    - Circuit breaker pattern
    - IP caching with TTL
    - Exponential backoff for failed IPs
    """
    
    # Default Cloudflare IP ranges
    DEFAULT_CF_RANGES = [
        "104.16.0.0/12",    # Main Cloudflare range
        "172.64.0.0/12",    # Additional ranges
        "172.65.0.0/12",
        "172.66.0.0/12",
        "172.67.0.0/12",
        "172.68.0.0/12",
        "172.69.0.0/12",
        "172.70.0.0/12",
        "172.71.0.0/12",
        "188.114.96.0/20",  # Newer ranges
        "188.114.97.0/20",
        "188.114.98.0/20",
        "188.114.99.0/20",
    ]
    
    # Common Cloudflare IPs (well-known, likely to work)
    COMMON_CF_IPS = [
        "104.16.0.0", "104.16.0.1", "104.16.1.0", "104.16.2.0",
        "104.16.3.0", "104.16.4.0", "104.16.5.0", "104.16.6.0",
        "104.16.7.0", "104.16.8.0", "104.16.9.0", "104.16.10.0",
        "104.17.0.0", "104.17.1.0", "104.17.2.0", "104.17.3.0",
        "104.17.4.0", "104.17.5.0", "104.17.6.0", "104.17.7.0",
        "172.64.0.0", "172.65.0.0", "172.66.0.0", "172.67.0.0",
        "172.68.0.0", "172.69.0.0", "172.70.0.0", "172.71.0.0",
        "188.114.96.0", "188.114.97.0", "188.114.98.0", "188.114.99.0",
    ]
    
    def __init__(
        self,
        ip_ranges: Optional[list[str]] = None,
        port: int = 443,
        timeout: float = 5.0,
        max_concurrent_tests: int = 10,
        circuit_breaker_threshold: int = 3,
        circuit_breaker_window: int = 60,
        circuit_breaker_cooldown: int = 300,
        logger=None,
    ):
        self.port = port
        self.timeout = timeout
        self.max_concurrent_tests = max_concurrent_tests
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_window = circuit_breaker_window
        self.circuit_breaker_cooldown = circuit_breaker_cooldown
        self.logger = logger
        
        # IP storage
        self._ips: dict[str, CloudflareIP] = {}
        self._working_ips: deque = deque()  # IPs that recently worked
        self._ip_cache: dict[str, float] = {}  # Cached working IPs with TTL
        
        # Initialize IPs from ranges
        self._initialize_ips(ip_ranges or self.DEFAULT_CF_RANGES)
    
    def _initialize_ips(self, ranges: list[str]):
        """Initialize IPs from CIDR ranges."""
        for cidr in ranges:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                # Limit to first 256 IPs per range to avoid too many
                for ip in list(network.hosts())[:256]:
                    ip_str = str(ip)
                    if ip_str not in self._ips:
                        self._ips[ip_str] = CloudflareIP(ip_str, self.port)
            except ValueError as e:
                if self.logger:
                    self.logger.warning(f"Invalid IP range: {cidr}, {e}")
        
        # Also add some common IPs
        for ip_str in self.COMMON_CF_IPS:
            if ip_str not in self._ips:
                self._ips[ip_str] = CloudflareIP(ip_str, self.port)
        
        if self.logger:
            self.logger.info(f"Initialized {len(self._ips)} Cloudflare IPs")
    
    async def test_latency(self, ip: str, port: int = 443) -> float:
        """Test latency to a specific IP."""
        start = time.perf_counter()
        try:
            # Try TCP connect first (faster than full TLS handshake)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            latency = (time.perf_counter() - start) * 1000  # Convert to ms
            writer.close()
            await writer.wait_closed()
            return latency
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return float('inf')
    
    async def test_ip(self, ip: CloudflareIP) -> CloudflareIP:
        """Test a single IP and update its latency."""
        latency = await self.test_latency(ip.ip, ip.port)
        ip.latency = latency
        return ip
    
    async def parallel_test_ips(self, ips: list[CloudflareIP]) -> list[CloudflareIP]:
        """Test multiple IPs in parallel."""
        tasks = [self.test_ip(ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        tested = []
        for result in results:
            if isinstance(result, CloudflareIP):
                tested.append(result)
        return tested
    
    async def find_best_ip(
        self,
        max_to_test: int = 20,
        prefer_latency_under: float = 200.0,
    ) -> Optional[CloudflareIP]:
        """
        Find the best IP by testing multiple in parallel.
        
        Args:
            max_to_test: Maximum number of IPs to test
            prefer_latency_under: Prefer IPs with latency under this value (ms)
        
        Returns:
            Best IP or None if no working IPs found
        """
        # First, check cached working IPs
        self._cleanup_cache()
        cached_ips = [self._ips[ip] for ip in self._ip_cache if ip in self._ips]
        
        # Sort by latency
        cached_ips.sort(key=lambda x: x.latency)
        
        # Test cached IPs first
        if cached_ips:
            for ip in cached_ips[:5]:
                if ip.should_try(self.circuit_breaker_cooldown):
                    latency = await self.test_latency(ip.ip, ip.port)
                    if latency < float('inf'):
                        ip.latency = latency
                        ip.success()
                        self._update_cache(ip.ip, latency)
                        if self.logger:
                            self.logger.log_ip_selection(ip.ip, latency, "cached")
                        return ip
        
        # Test random IPs if no cached working
        available_ips = [
            ip for ip in self._ips.values()
            if ip.should_try(self.circuit_breaker_cooldown)
        ]
        random.shuffle(available_ips)
        
        # Test in batches
        best_ip = None
        best_latency = float('inf')
        
        batch_size = min(self.max_concurrent_tests, max_to_test)
        for i in range(0, len(available_ips), batch_size):
            batch = available_ips[i:i + batch_size]
            results = await self.parallel_test_ips(batch)
            
            for ip in results:
                if ip.latency < float('inf') and ip.latency < best_latency:
                    best_ip = ip
                    best_latency = ip.latency
                    
                    # If we find a very fast IP, stop early
                    if ip.latency < prefer_latency_under:
                        ip.success()
                        self._update_cache(ip.ip, ip.latency)
                        if self.logger:
                            self.logger.log_ip_selection(ip.ip, ip.latency, "fast")
                        return ip
            
            # If we found any working IP, use the best one
            if best_ip:
                break
        
        if best_ip:
            best_ip.success()
            self._update_cache(best_ip.ip, best_ip.latency)
            if self.logger:
                self.logger.log_ip_selection(best_ip.ip, best_ip.latency, "tested")
        
        return best_ip
    
    def _update_cache(self, ip: str, latency: float):
        """Update IP cache with TTL."""
        # TTL based on latency (faster = longer cache)
        ttl = 300 if latency < 100 else 120 if latency < 200 else 60
        self._ip_cache[ip] = time.time() + ttl
        self._working_ips.append(ip)
    
    def _cleanup_cache(self):
        """Remove expired entries from cache."""
        now = time.time()
        expired = [ip for ip, expiry in self._ip_cache.items() if expiry < now]
        for ip in expired:
            self._ip_cache.pop(ip, None)
    
    def record_success(self, ip: str):
        """Record successful connection to an IP."""
        if ip in self._ips:
            self._ips[ip].success()
            self._update_cache(ip, self._ips[ip].latency)
    
    def record_failure(self, ip: str):
        """Record failed connection to an IP."""
        if ip in self._ips:
            ip_obj = self._ips[ip]
            ip_obj.failure()
            
            # Check circuit breaker
            if self._should_open_circuit(ip_obj):
                ip_obj.mark_unhealthy()
                if self.logger:
                    self.logger.log_circuit_breaker(ip, "OPENED")
    
    def _should_open_circuit(self, ip: CloudflareIP) -> bool:
        """Check if circuit breaker should open."""
        if ip.failure_count < self.circuit_breaker_threshold:
            return False
        
        # Check if failures are within the window
        time_since_first_failure = time.time() - ip.last_failure
        if time_since_first_failure > self.circuit_breaker_window:
            return False
        
        return True
    
    def get_next_ip(self) -> Optional[CloudflareIP]:
        """Get next available IP (for rotation)."""
        # First try cached working IPs
        self._cleanup_cache()
        
        for ip_str in list(self._working_ips):
            if ip_str in self._ips:
                ip = self._ips[ip_str]
                if ip.should_try(self.circuit_breaker_cooldown):
                    return ip
        
        # Fall back to any healthy IP
        for ip in self._ips.values():
            if ip.should_try(self.circuit_breaker_cooldown):
                return ip
        
        return None
    
    def get_all_ips(self) -> list[CloudflareIP]:
        """Get all managed IPs."""
        return list(self._ips.values())
    
    def get_working_ips(self) -> list[CloudflareIP]:
        """Get IPs that are currently working (healthy, low latency)."""
        self._cleanup_cache()
        return [
            ip for ip in self._ips.values()
            if ip.is_healthy and not ip.is_circuit_open and ip.latency < 1000
        ]
    
    def get_stats(self) -> dict:
        """Get IP manager statistics."""
        total = len(self._ips)
        healthy = sum(1 for ip in self._ips.values() if ip.is_healthy)
        circuit_open = sum(1 for ip in self._ips.values() if ip.is_circuit_open)
        cached = len(self._ip_cache)
        
        latencies = [ip.latency for ip in self._ips.values() if ip.latency < float('inf')]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        
        return {
            "total_ips": total,
            "healthy": healthy,
            "circuit_open": circuit_open,
            "cached": cached,
            "average_latency": avg_latency,
        }
    
    async def benchmark_ips(self, max_ips: int = 50) -> list[dict]:
        """
        Benchmark all IPs and return sorted results.
        
        Returns:
            List of dicts with ip, latency, status
        """
        # Get random sample of IPs to test
        all_ips = list(self._ips.values())
        random.shuffle(all_ips)
        to_test = all_ips[:max_ips]
        
        results = []
        for i in range(0, len(to_test), self.max_concurrent_tests):
            batch = to_test[i:i + self.max_concurrent_tests]
            tested = await self.parallel_test_ips(batch)
            
            for ip in tested:
                results.append({
                    "ip": ip.ip,
                    "latency": ip.latency if ip.latency < float('inf') else None,
                    "status": "OK" if ip.latency < float('inf') else "TIMEOUT",
                })
        
        # Sort by latency
        results.sort(key=lambda x: x.get('latency', float('inf')))
        
        return results


def expand_cidr(cidr: str, limit: int = 256) -> list[str]:
    """Expand CIDR notation to list of IPs (with limit)."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in list(network.hosts())[:limit]]
    except ValueError:
        return []


def load_ips_from_file(filepath: str) -> list[str]:
    """Load IPs from file (one per line)."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []