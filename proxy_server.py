"""
Asyncio-based proxy server for SNI-Spoofing.
Handles client connections and forwards traffic through the connection pool.
"""

import asyncio
import socket
import time
from typing import Optional, Dict
from dataclasses import dataclass


@dataclass
class ClientConnection:
    """Represents a client connection to the proxy."""
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    remote_conn: Optional[object] = None
    created_at: float = 0
    bytes_sent: int = 0
    bytes_received: int = 0


class ProxyServer:
    """
    Asyncio-based proxy server.
    
    Features:
    - Non-blocking I/O using asyncio
    - Efficient data forwarding
    - Connection tracking
    - Graceful shutdown
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1080,
        buffer_size: int = 32768,
        connection_manager=None,
        logger=None,
    ):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.connection_manager = connection_manager
        self.logger = logger
        
        # Server state
        self._server: Optional[asyncio.Server] = None
        self._is_running = False
        
        # Client connections
        self._clients: Dict[tuple, ClientConnection] = {}
        self._client_lock = asyncio.Lock()
        
        # Statistics
        self._stats = {
            "total_clients": 0,
            "active_clients": 0,
            "total_bytes_sent": 0,
            "total_bytes_received": 0,
            "errors": 0,
        }
    
    async def start(self):
        """Start the proxy server."""
        if self._is_running:
            return
        
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            reuse_address=True,
        )
        
        self._is_running = True
        
        addr = self._server.sockets[0].getsockname()
        if self.logger:
            self.logger.info(
                f"Proxy server started",
                host=self.host,
                port=self.port,
                buffer=self.buffer_size
            )
        
        print(f"\n{'='*60}")
        print(f"Proxy server listening on {addr[0]}:{addr[1]}")
        print(f"{'='*60}\n")
    
    async def stop(self):
        """Stop the proxy server gracefully."""
        self._is_running = False
        
        # Close all client connections
        async with self._client_lock:
            for client in list(self._clients.values()):
                try:
                    client.writer.close()
                    await asyncio.wait_for(client.writer.wait_closed(), timeout=2.0)
                except Exception:
                    pass
            self._clients.clear()
        
        # Close server
        if self._server:
            self._server.close()
            await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)
        
        if self.logger:
            self.logger.info("Proxy server stopped")
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a client connection."""
        client_addr = writer.get_extra_info('peername')
        client_id = client_addr if client_addr else ("unknown", 0)
        
        if self.logger:
            self.logger.debug(f"New client connection", client=client_addr)
        
        # Create client connection object
        client = ClientConnection(
            reader=reader,
            writer=writer,
            created_at=time.time(),
        )
        
        async with self._client_lock:
            self._clients[client_id] = client
            self._stats["total_clients"] += 1
            self._stats["active_clients"] = len(self._clients)
        
        try:
            # Get connection from pool
            if not self.connection_manager:
                if self.logger:
                    self.logger.error("No connection manager configured")
                return
            
            # Ensure we're connected
            if not self.connection_manager.is_connected():
                if self.logger:
                    self.logger.info("Connecting to remote...")
                connected = await self.connection_manager.connect()
                if not connected:
                    if self.logger:
                        self.logger.error("Failed to connect to remote")
                    return
            
            # Get connection from pool
            remote_conn = await self.connection_manager.get_connection()
            
            if not remote_conn:
                if self.logger:
                    self.logger.error("Failed to get remote connection")
                return
            
            # Start bidirectional forwarding
            await self._forward_data(
                client_reader=reader,
                client_writer=writer,
                remote_reader=remote_conn.reader,
                remote_writer=remote_conn.writer,
                client_id=client_id,
            )
            
            # Release connection back to pool
            await self.connection_manager.release_connection(remote_conn, healthy=True)
            
        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Client handler error",
                    client=client_addr,
                    error=str(e)
                )
            self._stats["errors"] += 1
        
        finally:
            # Clean up client connection
            async with self._client_lock:
                self._clients.pop(client_id, None)
                self._stats["active_clients"] = len(self._clients)
            
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass
            
            if self.logger:
                self.logger.debug(
                    f"Client disconnected",
                    client=client_addr,
                    sent=client.bytes_sent,
                    received=client.bytes_received
                )
    
    async def _forward_data(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        client_id: tuple,
    ):
        """Forward data between client and remote."""
        
        async def forward_client_to_remote():
            """Forward data from client to remote."""
            try:
                while True:
                    data = await asyncio.wait_for(
                        client_reader.read(self.buffer_size),
                        timeout=30.0
                    )
                    
                    if not data:
                        break
                    
                    remote_writer.write(data)
                    await asyncio.wait_for(
                        remote_writer.drain(),
                        timeout=30.0
                    )
                    
                    # Update stats
                    async with self._client_lock:
                        if client_id in self._clients:
                            self._clients[client_id].bytes_sent += len(data)
                        self._stats["total_bytes_sent"] += len(data)
                    
                    if self.logger:
                        self.logger.trace(
                            f"Forwarded to remote",
                            bytes=len(data)
                        )
                        
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Client->Remote forward error: {e}")
        
        async def forward_remote_to_client():
            """Forward data from remote to client."""
            try:
                while True:
                    data = await asyncio.wait_for(
                        remote_reader.read(self.buffer_size),
                        timeout=30.0
                    )
                    
                    if not data:
                        break
                    
                    client_writer.write(data)
                    await asyncio.wait_for(
                        client_writer.drain(),
                        timeout=30.0
                    )
                    
                    # Update stats
                    async with self._client_lock:
                        if client_id in self._clients:
                            self._clients[client_id].bytes_received += len(data)
                        self._stats["total_bytes_received"] += len(data)
                    
                    if self.logger:
                        self.logger.trace(
                            f"Forwarded to client",
                            bytes=len(data)
                        )
                        
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Remote->Client forward error: {e}")
        
        # Run both directions concurrently
        await asyncio.gather(
            forward_client_to_remote(),
            forward_remote_to_client(),
            return_exceptions=True
        )
    
    def get_stats(self) -> dict:
        """Get server statistics."""
        return {
            **self._stats,
            "active_clients": len(self._clients),
        }
    
    async def get_client_info(self) -> list[dict]:
        """Get info about active clients."""
        async with self._client_lock:
            return [
                {
                    "addr": str(k),
                    "connected": time.time() - v.created_at,
                    "bytes_sent": v.bytes_sent,
                    "bytes_received": v.bytes_received,
                }
                for k, v in self._clients.items()
            ]


class SimpleProxyServer:
    """
    Simplified proxy server for testing.
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1080,
        buffer_size: int = 32768,
        logger=None,
    ):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.logger = logger
        self._server = None
        self._remote_reader = None
        self._remote_writer = None
    
    async def set_remote_connection(self, reader, writer):
        """Set the remote connection to use."""
        self._remote_reader = reader
        self._remote_writer = writer
    
    async def start(self):
        """Start the server."""
        self._server = await asyncio.start_server(
            self._handle,
            self.host,
            self.port,
            reuse_address=True,
        )
        
        addr = self._server.sockets[0].getsockname()
        print(f"Proxy listening on {addr[0]}:{addr[1]}")
        
        async with self._server:
            await self._server.serve_forever()
    
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle client connection."""
        if not self._remote_reader or not self._remote_writer:
            writer.close()
            return
        
        async def forward(src, dst, direction):
            try:
                while True:
                    data = await src.read(self.buffer_size)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
        
        await asyncio.gather(
            forward(reader, self._remote_writer, "client->remote"),
            forward(self._remote_reader, writer, "remote->client"),
            return_exceptions=True
        )
        
        writer.close()
    
    async def stop(self):
        """Stop the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()


async def test_echo_server():
    """Simple echo server for testing."""
    server = await asyncio.start_server(
        lambda r, w: asyncio.create_task(echo(r, w)),
        '127.0.0.1',
        9999,
    )
    
    async with server:
        await server.serve_forever()


async def echo(reader, writer):
    """Echo handler."""
    while True:
        data = await reader.read(100)
        if not data:
            break
        writer.write(data)
        await writer.drain()
    writer.close()