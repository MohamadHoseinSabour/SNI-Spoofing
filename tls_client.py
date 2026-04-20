"""
TLS Client with advanced configuration for SNI-Spoofing.
Supports TLS 1.3, custom cipher suites, ALPN, and SNI rotation.
"""

import asyncio
import random
import ssl
import socket
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class TLSConfig:
    """TLS configuration parameters."""
    # SNI settings
    sni: str = "www.cloudflare.com"
    sni_list: list[str] = None
    
    # TLS version
    tls_version: str = "1.3"  # "1.2" or "1.3"
    
    # Certificate verification
    verify_ssl: bool = True
    
    # ALPN protocols
    alpn: list[str] = None
    
    # Cipher suites (TLS 1.3)
    cipher_suites: list[str] = None
    
    # Custom SSL context
    ssl_context: Optional[ssl.SSLContext] = None
    
    # Timeouts
    connect_timeout: float = 10.0
    handshake_timeout: float = 15.0
    
    def __post_init__(self):
        if self.sni_list is None:
            self.sni_list = [
                "www.cloudflare.com",
                "dash.cloudflare.com",
                "api.cloudflare.com",
                "blog.cloudflare.com",
                "developers.cloudflare.com",
            ]
        if self.alpn is None:
            self.alpn = ["h2", "http/1.1"]
        if self.cipher_suites is None:
            self.cipher_suites = [
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
            ]


class TLSClient:
    """
    Advanced TLS client with SNI spoofing capabilities.
    
    Features:
    - TLS 1.3 with modern cipher suites
    - ALPN support (h2, http/1.1)
    - SNI rotation and randomization
    - Custom SSL context configuration
    - Connection timeout handling
    """
    
    # Default TLS 1.3 cipher suites
    DEFAULT_CIPHERS_TLS13 = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
    ]
    
    # TLS 1.2 fallback ciphers
    DEFAULT_CIPHERS_TLS12 = [
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ]
    
    def __init__(self, config: TLSConfig, logger=None):
        self.config = config
        self.logger = logger
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._current_sni: str = config.sni
        
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with custom configuration."""
        # Determine TLS version
        if self.config.tls_version == "1.3":
            ssl_version = ssl.TLSVersion.TLSv1_3
        else:
            ssl_version = ssl.TLSVersion.TLSv1_2
        
        # Create context
        if self.config.ssl_context:
            # Use custom context if provided
            ctx = self.config.ssl_context
        else:
            # Create new context
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl_version
            ctx.maximum_version = ssl_version
        
        # Certificate verification
        ctx.verify_mode = ssl.CERT_REQUIRED if self.config.verify_ssl else ssl.CERT_NONE
        
        # Load default certs if verifying
        if self.config.verify_ssl:
            try:
                ctx.load_default_certs()
            except Exception:
                pass  # Continue without default certs
        
        # Set ALPN protocols
        if self.config.alpn:
            try:
                ctx.set_alpn_protocols(self.config.alpn)
            except NotImplementedError:
                if self.logger:
                    self.logger.debug("ALPN not supported on this system")
        
        # Set SNI
        self._current_sni = self._get_next_sni()
        
        return ctx
    
    def _get_next_sni(self) -> str:
        """Get next SNI from list (random selection)."""
        if self.config.sni_list and len(self.config.sni_list) > 1:
            return random.choice(self.config.sni_list)
        return self.config.sni
    
    def get_current_sni(self) -> str:
        """Get current SNI value."""
        return self._current_sni
    
    def rotate_sni(self) -> str:
        """Rotate to next SNI value."""
        self._current_sni = self._get_next_sni()
        if self.logger:
            self.logger.debug(f"Rotated SNI to: {self._current_sni}")
        return self._current_sni
    
    async def connect(
        self,
        host: str,
        port: int = 443,
        local_addr: Optional[tuple] = None,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, ssl.SSLObject]:
        """
        Establish TLS connection to target.
        
        Args:
            host: Target hostname/IP
            port: Target port
            local_addr: Optional local address to bind to
        
        Returns:
            Tuple of (reader, writer, ssl_object)
        """
        # Create fresh SSL context for this connection
        ctx = self._create_ssl_context()
        
        # Configure SNI
        self._current_sni = self._get_next_sni()
        
        # Wrap socket with SSL
        try:
            # Use asyncio to connect
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=host,
                    port=port,
                    ssl=ctx,
                    server_hostname=self._current_sni,
                    local_addr=local_addr,
                ),
                timeout=self.config.connect_timeout
            )
            
            # Get SSL object for additional info
            ssl_obj = writer.get_extra_info('ssl')
            
            if self.logger:
                self.logger.log_tls_handshake(
                    host,
                    self._current_sni,
                    True,
                    protocol=ssl_obj.version() if ssl_obj else "unknown"
                )
            
            return reader, writer, ssl_obj
            
        except asyncio.TimeoutError as e:
            if self.logger:
                self.logger.log_tls_handshake(host, self._current_sni, False, error="timeout")
            raise TimeoutError(f"Connection timeout to {host}:{port}") from e
            
        except ssl.SSLError as e:
            if self.logger:
                self.logger.log_tls_handshake(host, self._current_sni, False, error=str(e))
            raise
            
        except Exception as e:
            if self.logger:
                self.logger.log_tls_handshake(host, self._current_sni, False, error=str(e))
            raise
    
    async def connect_with_retry(
        self,
        host: str,
        port: int = 443,
        max_retries: int = 5,
        retry_delays: list[float] = None,
        local_addr: Optional[tuple] = None,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, ssl.SSLObject]:
        """
        Connect with automatic retry and exponential backoff.
        
        Args:
            host: Target hostname/IP
            port: Target port
            max_retries: Maximum retry attempts
            retry_delays: List of delay seconds between retries
            local_addr: Optional local address to bind to
        
        Returns:
            Tuple of (reader, writer, ssl_object)
        """
        if retry_delays is None:
            retry_delays = [1, 2, 4, 8, 15]
        
        last_error = None
        
        for attempt in range(max_retries):
            try:
                return await self.connect(host, port, local_addr)
                
            except (TimeoutError, ssl.SSLError, OSError) as e:
                last_error = e
                
                if attempt < max_retries - 1:
                    delay = retry_delays[min(attempt, len(retry_delays) - 1)]
                    if self.logger:
                        self.logger.log_reconnect(host, attempt + 1, max_retries, delay=f"{delay}s")
                    await asyncio.sleep(delay)
                else:
                    if self.logger:
                        self.logger.error(
                            f"Connection failed after {max_retries} attempts",
                            ip=host, port=port
                        )
        
        raise last_error or ConnectionError(f"Failed to connect to {host}:{port}")
    
    def get_ssl_info(self, ssl_obj: ssl.SSLObject) -> dict:
        """Get SSL connection information."""
        try:
            return {
                "version": ssl_obj.version(),
                "cipher": ssl_obj.cipher(),
                "protocol": ssl_obj.selected_alpn_protocol(),
                "compression": ssl_obj.compression(),
            }
        except Exception:
            return {}


class SNIManager:
    """
    Manages SNI values for rotation and randomization.
    """
    
    DEFAULT_SNI_LIST = [
        "www.cloudflare.com",
        "dash.cloudflare.com",
        "api.cloudflare.com",
        "blog.cloudflare.com",
        "developers.cloudflare.com",
        "cloudflare.com",
        "ssl.cloudflare.com",
    ]
    
    def __init__(self, sni_list: Optional[list[str]] = None, custom_sni: Optional[str] = None):
        """
        Initialize SNI manager.
        
        Args:
            sni_list: List of SNI values to use
            custom_sni: Single custom SNI value (takes priority)
        """
        if custom_sni:
            self._sni_list = [custom_sni]
        elif sni_list:
            self._sni_list = sni_list
        else:
            self._sni_list = self.DEFAULT_SNI_LIST
        
        self._current_index = 0
        self._use_random = True
    
    def get_next(self) -> str:
        """Get next SNI (rotating or random)."""
        if self._use_random:
            return random.choice(self._sni_list)
        else:
            sni = self._sni_list[self._current_index]
            self._current_index = (self._current_index + 1) % len(self._sni_list)
            return sni
    
    def get_random(self) -> str:
        """Get random SNI."""
        return random.choice(self._sni_list)
    
    def get_all(self) -> list[str]:
        """Get all configured SNIs."""
        return self._sni_list.copy()
    
    def set_mode(self, random_mode: bool):
        """Set selection mode (random vs rotating)."""
        self._use_random = random_mode


def create_tls_context(
    sni: str = "www.cloudflare.com",
    tls_version: str = "1.3",
    verify: bool = True,
    alpn: list[str] = None,
) -> ssl.SSLContext:
    """
    Create a configured SSL context.
    
    Args:
        sni: SNI hostname
        tls_version: TLS version ("1.2" or "1.3")
        verify: Whether to verify certificates
        alpn: List of ALPN protocols
    
    Returns:
        Configured SSL context
    """
    if tls_version == "1.3":
        ssl_version = ssl.TLSVersion.TLSv1_3
    else:
        ssl_version = ssl.TLSVersion.TLSv1_2
    
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl_version
    ctx.maximum_version = ssl_version
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    
    if verify:
        ctx.load_default_certs()
    
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except NotImplementedError:
            pass
    
    return ctx