"""
Connection Pool for managing persistent TLS connections.
Implements connection pooling, health checks, and automatic reconnection.
"""

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
from collections import deque


@dataclass
class PooledConnection:
    """Represents a pooled TLS connection."""
    id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    ssl_object: Optional[object] = None
    remote_ip: str = ""
    remote_port: int = 443
    sni: str = ""
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    is_healthy: bool = True
    use_count: int = 0
    error_count: int = 0
    
    def mark_used(self):
        """Mark connection as used."""
        self.last_used = time.time()
        self.use_count += 1
    
    def mark_healthy(self):
        """Mark connection as healthy."""
        self.is_healthy = True
        self.error_count = 0
    
    def mark_unhealthy(self, error: str = ""):
        """Mark connection as unhealthy."""
        self.is_healthy = False
        self.error_count += 1
    
    def age(self) -> float:
        """Get connection age in seconds."""
        return time.time() - self.created_at
    
    def idle_time(self) -> float:
        """Get idle time in seconds."""
        return time.time() - self.last_used
    
    async def close(self):
        """Close the connection."""
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


class ConnectionPool:
    """
    Manages a pool of persistent TLS connections.
    
    Features:
    - Configurable pool size
    - Connection health tracking
    - Automatic reconnection on failure
    - Connection reuse
    - Graceful shutdown
    """
    
    def __init__(
        self,
        max_size: int = 5,
        min_size: int = 1,
        max_idle_time: float = 60.0,
        connection_timeout: float = 10.0,
        read_timeout: float = 300.0,
        write_timeout: float = 30.0,
        tcp_nodelay: bool = True,
        keepalive: bool = True,
        keepalive_idle: int = 60,
        keepalive_interval: int = 10,
        keepalive_count: int = 5,
        logger=None,
    ):
        self.max_size = max_size
        self.min_size = min_size
        self.max_idle_time = max_idle_time
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.write_timeout = write_timeout
        self.tcp_nodelay = tcp_nodelay
        self.keepalive = keepalive
        self.keepalive_idle = keepalive_idle
        self.keepalive_interval = keepalive_interval
        self.keepalive_count = keepalive_count
        self.logger = logger
        
        # Connection storage
        self._connections: Dict[str, PooledConnection] = {}
        self._available: deque = deque()
        self._lock = asyncio.Lock()
        
        # Statistics
        self._stats = {
            "total_created": 0,
            "total_closed": 0,
            "total_reused": 0,
            "total_errors": 0,
        }
        
        # Current target
        self._current_ip: Optional[str] = None
        self._current_port: int = 443
        self._current_sni: str = "www.cloudflare.com"
        self._tls_client = None
    
    def set_tls_client(self, tls_client):
        """Set the TLS client for creating connections."""
        self._tls_client = tls_client
    
    async def set_target(self, ip: str, port: int = 443, sni: str = "www.cloudflare.com"):
        """Set the current target for connections."""
        async with self._lock:
            # Close all existing connections if target changed
            if self._current_ip != ip:
                await self._close_all()
                self._current_ip = ip
                self._current_port = port
                self._current_sni = sni
    
    async def acquire(self) -> Optional[PooledConnection]:
        """
        Acquire a connection from the pool.
        
        Returns:
            PooledConnection or None if unavailable
        """
        async with self._lock:
            # Try to get an available connection
            while self._available:
                conn = self._available.popleft()
                
                # Check if connection is still healthy
                if conn.is_healthy and not conn.writer.is_closing():
                    conn.mark_used()
                    self._stats["total_reused"] += 1
                    if self.logger:
                        self.logger.debug(
                            f"Reused connection",
                            ip=conn.remote_ip, uses=conn.use_count
                        )
                    return conn
                else:
                    # Close unhealthy connection
                    await conn.close()
                    self._stats["total_closed"] += 1
            
            # Create new connection if pool not full
            if len(self._connections) < self.max_size:
                return None  # Signal to create new connection
            
            # Pool is full, wait
            return None
    
    async def create_connection(
        self,
        ip: str,
        port: int,
        sni: str,
    ) -> Optional[PooledConnection]:
        """
        Create a new TLS connection.
        
        Args:
            ip: Target IP
            port: Target port
            sni: SNI hostname
        
        Returns:
            New PooledConnection or None on failure
        """
        if not self._tls_client:
            if self.logger:
                self.logger.error("TLS client not set")
            return None
        
        try:
            reader, writer, ssl_obj = await self._tls_client.connect(ip, port)
            
            # Configure socket options
            if self.tcp_nodelay:
                writer.get_extra_info('socket').setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
                )
            
            conn_id = f"{ip}:{port}:{sni}:{id(writer)}"
            conn = PooledConnection(
                id=conn_id,
                reader=reader,
                writer=writer,
                ssl_object=ssl_obj,
                remote_ip=ip,
                remote_port=port,
                sni=sni,
            )
            
            async with self._lock:
                self._connections[conn_id] = conn
                self._stats["total_created"] += 1
            
            if self.logger:
                self.logger.log_connection(ip, sni, True, latency=0)
            
            return conn
            
        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Failed to create connection",
                    ip=ip, port=port, sni=sni, error=str(e)
                )
                self.logger.log_connection(ip, sni, False)
            self._stats["total_errors"] += 1
            return None
    
    async def release(self, conn: PooledConnection, healthy: bool = True):
        """
        Release a connection back to the pool.
        
        Args:
            conn: The connection to release
            healthy: Whether the connection is still healthy
        """
        async with self._lock:
            if not healthy:
                conn.mark_unhealthy()
                await conn.close()
                self._connections.pop(conn.id, None)
                self._stats["total_closed"] += 1
                return
            
            # Mark healthy and add to available
            conn.mark_healthy()
            
            # Don't reuse connections that are too old
            if conn.age() > self.max_idle_time * 2:
                await conn.close()
                self._connections.pop(conn.id, None)
                self._stats["total_closed"] += 1
                return
            
            # Add to available pool
            if conn.id in self._connections:
                self._available.append(conn)
    
    async def remove(self, conn: PooledConnection):
        """Remove a connection from the pool."""
        async with self._lock:
            await conn.close()
            self._connections.pop(conn.id, None)
            self._stats["total_closed"] += 1
    
    async def _close_all(self):
        """Close all connections in the pool."""
        for conn in list(self._connections.values()):
            try:
                await conn.close()
            except Exception:
                pass
        
        self._connections.clear()
        self._available.clear()
    
    async def close(self):
        """Close all connections and shutdown the pool."""
        await self._close_all()
    
    async def health_check(self) -> Dict[str, bool]:
        """
        Check health of all connections.
        
        Returns:
            Dict of connection_id -> is_healthy
        """
        results = {}
        
        async with self._lock:
            conns_to_check = list(self._connections.values())
        
        for conn in conns_to_check:
            try:
                # Try a quick read to check if connection is alive
                if conn.writer.is_closing():
                    results[conn.id] = False
                    continue
                
                # Send a ping (empty write)
                conn.writer.write(b'')
                await asyncio.wait_for(
                    conn.writer.drain(),
                    timeout=2.0
                )
                results[conn.id] = True
                conn.mark_healthy()
                
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Health check failed", conn=conn.id, error=str(e))
                results[conn.id] = False
                conn.mark_unhealthy(str(e))
                
                # Remove unhealthy connection
                async with self._lock:
                    self._connections.pop(conn.id, None)
        
        return results
    
    async def cleanup_idle(self):
        """Remove idle connections beyond min_size."""
        async with self._lock:
            while len(self._connections) > self.min_size and self._available:
                conn = self._available.popleft()
                if conn.id in self._connections:
                    await conn.close()
                    self._connections.pop(conn.id)
                    self._stats["total_closed"] += 1
    
    def get_stats(self) -> dict:
        """Get pool statistics."""
        return {
            **self._stats,
            "current_size": len(self._connections),
            "available": len(self._available),
            "target": f"{self._current_ip}:{self._current_port}" if self._current_ip else "none",
        }
    
    async def get_connection_info(self) -> list[dict]:
        """Get detailed info about all connections."""
        async with self._lock:
            return [
                {
                    "id": conn.id,
                    "ip": conn.remote_ip,
                    "port": conn.remote_port,
                    "sni": conn.sni,
                    "healthy": conn.is_healthy,
                    "age": conn.age(),
                    "idle": conn.idle_time(),
                    "uses": conn.use_count,
                }
                for conn in self._connections.values()
            ]


class ConnectionManager:
    """
    High-level connection manager with retry logic and IP rotation.
    
    Coordinates between IP manager, TLS client, and connection pool.
    """
    
    def __init__(
        self,
        ip_manager,
        tls_client,
        pool: ConnectionPool,
        max_retries: int = 5,
        retry_delays: list[float] = None,
        logger=None,
    ):
        self.ip_manager = ip_manager
        self.tls_client = tls_client
        self.pool = pool
        self.max_retries = max_retries
        self.retry_delays = retry_delays or [1, 2, 4, 8, 15]
        self.logger = logger
        
        # Set TLS client in pool
        pool.set_tls_client(tls_client)
        
        # State
        self._current_ip: Optional[str] = None
        self._current_sni: str = "www.cloudflare.com"
        self._is_connected = False
    
    async def connect(self) -> bool:
        """
        Establish connection with automatic IP selection and retry.
        
        Returns:
            True if connected successfully
        """
        # Find best IP
        best_ip = await self.ip_manager.find_best_ip()
        
        if not best_ip:
            if self.logger:
                self.logger.error("No working Cloudflare IPs found")
            return False
        
        self._current_ip = best_ip.ip
        self._current_sni = self.tls_client.get_current_sni()
        
        # Update pool target
        await self.pool.set_target(
            self._current_ip,
            443,
            self._current_sni
        )
        
        # Try to create connection with retries
        for attempt in range(self.max_retries):
            conn = await self.pool.create_connection(
                self._current_ip,
                443,
                self._current_sni
            )
            
            if conn:
                self._is_connected = True
                self.ip_manager.record_success(self._current_ip)
                return True
            
            # Retry with backoff
            if attempt < self.max_retries - 1:
                delay = self.retry_delays[min(attempt, len(self.retry_delays) - 1)]
                if self.logger:
                    self.logger.log_reconnect(
                        self._current_ip,
                        attempt + 1,
                        self.max_retries,
                        delay=f"{delay}s"
                    )
                await asyncio.sleep(delay)
                
                # Try next IP
                next_ip = self.ip_manager.get_next_ip()
                if next_ip:
                    self._current_ip = next_ip.ip
                    self._current_sni = self.tls_client.rotate_sni()
        
        # All retries failed
        if self._current_ip:
            self.ip_manager.record_failure(self._current_ip)
        
        if self.logger:
            self.logger.error(
                f"Failed to connect after {self.max_retries} attempts"
            )
        
        return False
    
    async def get_connection(self) -> Optional[PooledConnection]:
        """Get a connection from the pool."""
        return await self.pool.acquire()
    
    async def release_connection(self, conn: PooledConnection, healthy: bool = True):
        """Release connection back to pool."""
        await self.pool.release(conn, healthy)
    
    async def reconnect(self) -> bool:
        """Attempt to reconnect."""
        self._is_connected = False
        return await self.connect()
    
    async def close(self):
        """Close all connections."""
        await self.pool.close()
        self._is_connected = False
    
    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._is_connected
    
    def get_current_endpoint(self) -> tuple:
        """Get current IP and SNI."""
        return self._current_ip, self._current_sni