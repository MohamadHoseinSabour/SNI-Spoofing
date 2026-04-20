"""
SNI-Spoofing Proxy - Main Entry Point
Refactored version with intelligent IP management, connection pooling, and health monitoring.
"""

import asyncio
import os
import signal
import sys
import time
from typing import Optional

# Import our modules
from config import parse_arguments, ProxyConfig, create_default_config_file
from logger import get_logger, StructuredLogger
from ip_manager import IPManager
from tls_client import TLSClient, TLSConfig
from connection_pool import ConnectionPool, ConnectionManager
from health_monitor import HealthMonitor, PoolHealthMonitor, MetricsCollector
from proxy_server import ProxyServer


class SNISpoofingProxy:
    """
    Main application class coordinating all components.
    """
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.logger: Optional[StructuredLogger] = None
        self.ip_manager: Optional[IPManager] = None
        self.tls_client: Optional[TLSClient] = None
        self.connection_pool: Optional[ConnectionPool] = None
        self.connection_manager: Optional[ConnectionManager] = None
        self.health_monitor: Optional[HealthMonitor] = None
        self.proxy_server: Optional[ProxyServer] = None
        self.metrics: Optional[MetricsCollector] = None
        
        # State
        self._is_running = False
        self._start_time = 0
    
    async def initialize(self):
        """Initialize all components."""
        # Setup logger
        self.logger = get_logger(
            name="SNI-Spoofing",
            verbose=self.config.verbose,
            log_file=self.config.log_file
        )
        
        self.logger.info(
            "Initializing SNI-Spoofing Proxy",
            version="2.0.0",
            verbose_level=self.config.verbose
        )
        
        # Initialize IP Manager
        self.ip_manager = IPManager(
            ip_ranges=self.config.cf_ips,
            port=self.config.remote_port,
            timeout=self.config.connect_timeout,
            max_concurrent_tests=10,
            circuit_breaker_threshold=self.config.circuit_breaker_threshold,
            circuit_breaker_window=self.config.circuit_breaker_window,
            circuit_breaker_cooldown=self.config.circuit_breaker_cooldown,
            logger=self.logger,
        )
        
        # Initialize TLS Client
        tls_config = TLSConfig(
            sni=self.config.sni,
            sni_list=self.config.sni_list,
            tls_version=self.config.tls_version,
            verify_ssl=self.config.verify_ssl,
            alpn=self.config.alpn,
            connect_timeout=self.config.connect_timeout,
        )
        self.tls_client = TLSClient(tls_config, logger=self.logger)
        
        # Initialize Connection Pool
        self.connection_pool = ConnectionPool(
            max_size=self.config.pool_size,
            min_size=1,
            max_idle_time=60.0,
            connection_timeout=self.config.connect_timeout,
            read_timeout=self.config.read_timeout,
            write_timeout=self.config.write_timeout,
            tcp_nodelay=self.config.tcp_nodelay,
            keepalive=self.config.keepalive,
            keepalive_idle=self.config.keepalive_idle,
            keepalive_interval=self.config.keepalive_interval,
            keepalive_count=self.config.keepalive_count,
            logger=self.logger,
        )
        
        # Initialize Connection Manager
        self.connection_manager = ConnectionManager(
            ip_manager=self.ip_manager,
            tls_client=self.tls_client,
            pool=self.connection_pool,
            max_retries=self.config.max_retries,
            retry_delays=self.config.retry_delays,
            logger=self.logger,
        )
        
        # Initialize Health Monitor
        self.health_monitor = PoolHealthMonitor(
            connection_pool=self.connection_pool,
            check_interval=self.config.health_check_interval,
            timeout=self.config.health_check_timeout,
            max_consecutive_failures=3,
            logger=self.logger,
        )
        
        # Set up recovery callback
        async def on_unhealthy():
            self.logger.warning("Connection unhealthy, attempting reconnection...")
            await self.connection_manager.reconnect()
        
        async def on_recovered():
            self.logger.info("Connection recovered")
        
        self.health_monitor.on_unhealthy = on_unhealthy
        self.health_monitor.on_recovered = on_recovered
        
        # Initialize Metrics Collector
        self.metrics = MetricsCollector(logger=self.logger)
        
        # Initialize Proxy Server
        self.proxy_server = ProxyServer(
            host=self.config.local_host,
            port=self.config.local_port,
            buffer_size=self.config.buffer_size,
            connection_manager=self.connection_manager,
            logger=self.logger,
        )
        
        self.logger.info("Initialization complete")
    
    async def start(self):
        """Start the proxy."""
        if self._is_running:
            return
        
        self._is_running = True
        self._start_time = time.time()
        
        self.logger.info(
            "Starting SNI-Spoofing Proxy",
            local=f"{self.config.local_host}:{self.config.local_port}",
            pool_size=self.config.pool_size
        )
        
        # Start health monitor
        await self.health_monitor.start()
        
        # Start proxy server
        await self.proxy_server.start()
        
        # Initial connection (if not on-demand)
        if self.config.connection_mode == "persistent":
            self.logger.info("Establishing persistent connection...")
            await self.connection_manager.connect()
        
        self.logger.info("Proxy is running. Press Ctrl+C to stop.")
    
    async def stop(self):
        """Stop the proxy gracefully."""
        self.logger.info("Stopping SNI-Spoofing Proxy...")
        
        # Stop accepting new connections
        if self.proxy_server:
            await self.proxy_server.stop()
        
        # Stop health monitor
        if self.health_monitor:
            await self.health_monitor.stop()
        
        # Close connection manager
        if self.connection_manager:
            await self.connection_manager.close()
        
        # Print final stats
        uptime = time.time() - self._start_time
        self.logger.info(f"Total uptime: {uptime:.1f}s")
        
        if self.metrics:
            await self.metrics.print_summary()
        
        if self.logger:
            self.logger.close()
        
        self._is_running = False
    
    async def run_forever(self):
        """Run the proxy until stopped."""
        await self.start()
        
        # Keep running
        try:
            while self._is_running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass


async def benchmark_ips(config: ProxyConfig, logger: StructuredLogger):
    """Run IP benchmark mode."""
    logger.info("Starting IP benchmark...")
    
    ip_manager = IPManager(
        ip_ranges=config.cf_ips,
        port=config.remote_port,
        timeout=5.0,
        max_concurrent_tests=10,
        logger=logger,
    )
    
    results = await ip_manager.benchmark_ips(max_ips=50)
    
    print("\n" + "=" * 70)
    print("BENCHMARK RESULTS - Cloudflare IPs (sorted by latency)")
    print("=" * 70)
    print(f"{'IP':<20} {'Latency (ms)':<15} {'Status':<10}")
    print("-" * 70)
    
    for i, result in enumerate(results[:20], 1):
        ip = result['ip']
        latency = result.get('latency')
        status = result['status']
        
        latency_str = f"{latency:.2f}" if latency else "TIMEOUT"
        print(f"{ip:<20} {latency_str:<15} {status:<10}")
    
    print("-" * 70)
    print(f"Tested {len(results)} IPs total")
    print("=" * 70 + "\n")
    
    # Show top 5 recommendations
    working = [r for r in results if r.get('latency')]
    if working:
        print("Top 5 recommended IPs:")
        for i, r in enumerate(working[:5], 1):
            print(f"  {i}. {r['ip']} ({r['latency']:.2f}ms)")
        print()


async def test_connectivity(config: ProxyConfig, logger: StructuredLogger):
    """Test connectivity mode."""
    logger.info("Testing connectivity...")
    
    ip_manager = IPManager(
        ip_ranges=config.cf_ips,
        port=config.remote_port,
        timeout=config.connect_timeout,
        logger=logger,
    )
    
    # Find best IP
    best_ip = await ip_manager.find_best_ip(max_to_test=20)
    
    if best_ip:
        logger.info(
            "Connectivity test PASSED",
            ip=best_ip.ip,
            latency=f"{best_ip.latency:.2f}ms"
        )
        print(f"\nBest IP: {best_ip.ip}")
        print(f"Latency: {best_ip.latency:.2f}ms")
        return 0
    else:
        logger.error("Connectivity test FAILED - no working IPs found")
        return 1


def setup_signal_handlers(proxy: SNISpoofingProxy, loop: asyncio.AbstractEventLoop):
    """Setup signal handlers for graceful shutdown."""
    
    def signal_handler(sig):
        print("\n\nShutdown signal received, stopping...")
        loop.create_task(proxy.stop())
    
    # Windows doesn't support SIGTERM, use SIGINT
    if sys.platform == "win32":
        signal.signal(signal.SIGINT, lambda s, f: signal_handler(s))
    else:
        signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s))
        signal.signal(signal.SIGINT, lambda s, f: signal_handler(s))


async def async_main():
    """Async main entry point."""
    # Parse arguments
    config = parse_arguments()
    
    # Create proxy instance
    proxy = SNISpoofingProxy(config)
    
    # Setup signal handlers
    loop = asyncio.get_event_loop()
    setup_signal_handlers(proxy, loop)
    
    # Handle special modes
    if config.benchmark_mode:
        # Initialize logger for benchmark
        logger = get_logger("SNI-Spoofing", config.verbose, config.log_file)
        await benchmark_ips(config, logger)
        logger.close()
        return
    
    if config.test_mode:
        # Initialize logger for test
        logger = get_logger("SNI-Spoofing", config.verbose, config.log_file)
        exit_code = await test_connectivity(config, logger)
        logger.close()
        sys.exit(exit_code)
    
    # Normal mode: run the proxy
    await proxy.initialize()
    await proxy.run_forever()


def main():
    """Main entry point."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# Core configuration
LISTEN_HOST = config.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = config.get("LISTEN_PORT", 40443)

# Connection mode: "on_demand" or "persistent"
CONNECTION_MODE = config.get("CONNECTION_MODE", "on_demand")
PERSISTENT_RECONNECT_DELAY = config.get("PERSISTENT_RECONNECT_DELAY", 5)

# Support for SNI-IP pairs + fallbacks
SNI_IP_PAIRS = config.get("SNI_IP_PAIRS", [])
FALLBACK_IPS = config.get("FALLBACK_IPS", ["188.114.98.0"])
FALLBACK_SNIS = config.get("FALLBACK_SNIS", ["auth.vercel.com"])
CONNECT_PORT = config.get("CONNECT_PORT", 443)

# Current active IP/SNI (will be set after successful connection)
CURRENT_CONNECT_IP = None
CURRENT_FAKE_SNI = None

# Advanced configuration
RETRY_COUNT = config.get("RETRY_COUNT", 3)
RETRY_DELAY = config.get("RETRY_DELAY", 1.5)
CONNECTION_TIMEOUT = config.get("CONNECTION_TIMEOUT", 10)
RELAY_BUFFER_SIZE = config.get("RELAY_BUFFER_SIZE", 65575)
KEEPALIVE_IDLE = config.get("KEEPALIVE_IDLE", 11)
KEEPALIVE_INTERVAL = config.get("KEEPALIVE_INTERVAL", 2)
KEEPALIVE_COUNT = config.get("KEEPALIVE_COUNT", 3)
BYPASS_METHOD = config.get("BYPASS_METHOD", "wrong_seq")
LOG_LEVEL = config.get("LOG_LEVEL", "info")

# Update logging level
logger = setup_logging(LOG_LEVEL)

# Verbose mode
VERBOSE = config.get("VERBOSE", True)
SHOW_STATUS = config.get("SHOW_STATUS", True)

# Get interface IP (use first fallback IP)
INTERFACE_IPV4 = get_default_interface_ipv4(FALLBACK_IPS[0] if FALLBACK_IPS else "8.8.8.8")
DATA_MODE = "tls"

# Graceful shutdown flag
shutdown_event = asyncio.Event()
active_connections: int = 0
connection_lock = threading.Lock()

# Statistics
total_snis_tested = 0
total_snis_loaded = 0
current_status = "IDLE"


def get_terminal_width():
    """Get terminal width"""
    try:
        return os.get_terminal_size().columns
    except:
        return 80


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')



# --- LOG BUFFER & FIXED HEADER ---
LOG_BUFFER = []
MAX_LOG_LINES = 20

def print_header():
    """Print fixed header - responsive, stays at top, no ANSI for Windows"""
    global total_snis_loaded
    total_snis_loaded = len(SNI_IP_PAIRS) + len(FALLBACK_SNIS)
    width = get_terminal_width()
    if width < 60:
        width = 60
    mode_icon = "⚡" if CONNECTION_MODE == "on_demand" else "🔒"
    mode_text = "ON-DEMAND" if CONNECTION_MODE == "on_demand" else "PERSISTENT"
    print("\n" + "+" + "-"*(width-2) + "+")
    print("|" + " SNI SPOOFING - DPI BYPASSER ".center(width-2) + "|")
    print("+" + "-"*(width-2) + "+")
    # Config rows
    configs = [
        ("Listen", f"{LISTEN_HOST}:{LISTEN_PORT}"),
        ("Interface", INTERFACE_IPV4),
        ("Target", f"{CONNECT_PORT}"),
        ("Retries", f"{RETRY_COUNT}x/{RETRY_DELAY}s"),
        ("Bypass", BYPASS_METHOD),
        ("Mode", f"{mode_icon} {mode_text}"),
    ]
    col_width = (width - 4) // 2
    for i in range(0, len(configs), 2):
        left = configs[i]
        right = configs[i+1] if i+1 < len(configs) else ("", "")
        left_label = left[0].ljust(10)
        left_val = left[1][:col_width-12].ljust(col_width-12)
        right_label = right[0].ljust(10) if right[0] else ""
        right_val = right[1][:col_width-12] if right[1] else ""
        print(f"|  {left_label} {left_val}  {right_label} {right_val} |")
    print("+" + "-"*(width-2) + "+")
    sni_count = str(len(SNI_IP_PAIRS))
    fb_ips = str(len(FALLBACK_IPS))
    fb_snis = str(len(FALLBACK_SNIS))
    stats = f"SNI Pairs: {sni_count}  Fallbacks: {fb_ips} IPs / {fb_snis} SNIs"
    print(f"|  {stats}{' '*(width-4-len(stats))}|")
    print("+" + "-"*(width-2) + "+")

def redraw_screen():
    clear_screen()
    print_header()
    print_status_bar()
    print_log_area()
    for line in LOG_BUFFER[-MAX_LOG_LINES:]:
        print(line)


def print_status_bar():
    """Print status bar - fixed below header"""
    global current_status, total_snis_tested
    
    width = get_terminal_width()
    if width < 60:
        width = 60
    
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    
    # Status color
    status_color = GREEN if current_status == "CONNECTED" else YELLOW if current_status == "CONNECTING" else RED if current_status == "FAILED" else BLUE
    
    # Build status line
    status_str = f"{status_color}●{RESET} {current_status}"
    tested_str = f"Tested: {total_snis_tested}/{total_snis_loaded}"
    conn_str = f"→ {CURRENT_CONNECT_IP or '---'}:{CONNECT_PORT}"
    sni_str = f"SNI: {CURRENT_FAKE_SNI or '---'}"
    
    # Pad to width
    line = f" {status_str:<18} {tested_str:<15} {conn_str:<22} {sni_str}"
    line = line[:width-2].ljust(width-2)
    
    print(f"{BOLD}├{'─'*(width-2)}┤{RESET}")
    print(f"{BOLD}│{RESET} {line} {BOLD}│{RESET}")
    print(f"{BOLD}├{'─'*(width-2)}┤{RESET}")


def print_log_area():
    """Print log section header"""
    width = get_terminal_width()
    if width < 60:
        width = 60
    
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    
    print(f"{BOLD}│{RESET} {CYAN}▼ Logs (Ctrl+C: stop | M: switch mode){RESET}{' '*(width-40)} {BOLD}│{RESET}")
    print(f"{BOLD}├{'─'*(width-2)}┤{RESET}")


def print_status(message: str, level: str = "info", show_ip: bool = True):
    """Print status message and redraw screen with fixed header"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    symbol = {"success": "[✓]", "error": "[✗]", "warning": "[!]", "info": "[●]", "trying": "[○]"}.get(level, "[?]")
    extra = ""
    if show_ip and CURRENT_CONNECT_IP and CURRENT_FAKE_SNI:
        extra = f" [→ {CURRENT_CONNECT_IP}:{CONNECT_PORT} SNI:{CURRENT_FAKE_SNI}]"
    log_line = f"{symbol} {timestamp} {message}{extra}"
    LOG_BUFFER.append(log_line)
    if len(LOG_BUFFER) > MAX_LOG_LINES:
        del LOG_BUFFER[0]
    redraw_screen()
    # Also log
    if level == "success":
        logger.info(message)
    elif level == "error":
        logger.error(message)
    elif level == "warning":
        logger.warning(message)
    else:
        logger.debug(message)


def print_connection_status(status: str, ip: str = None, sni: str = None):
    """Print connection status with colors"""
    RESET = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    GRAY = "\033[90m"
    
    status_config = {
        "connecting": (YELLOW + "○" + RESET, f"→ {ip}:{CONNECT_PORT} SNI: {sni}"),
        "connected": (GREEN + "✓" + RESET, f"CONNECTED {ip}:{CONNECT_PORT} SNI: {sni}"),
        "failed": (RED + "✗" + RESET, f"Failed {ip}:{CONNECT_PORT}"),
        "retrying": (YELLOW + "↻" + RESET, f"Retry {ip}:{CONNECT_PORT}"),
        "trying_next": (BLUE + "→" + RESET, "Trying next..."),
        "fallback": (YELLOW + "⬇" + RESET, f"Fallback {ip}:{CONNECT_PORT} SNI: {sni}"),
        "waiting": (BLUE + "●" + RESET, f"Waiting... {sni}"),
    }
    
    symbol, msg = status_config.get(status, (GRAY + "?" + RESET, status))
    
    if SHOW_STATUS:
        print(f"{symbol} {msg}")

##################

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}

# Persistent connection manager
class PersistentConnectionManager:
    """Manages persistent connection for v2ray clients"""
    
    def __init__(self):
        self.outgoing_sock = None
        self.fake_injective_conn = None
        self.connected = False
        self.current_ip = None
        self.current_sni = None
        self.lock = asyncio.Lock()
        self.reconnect_task = None
        self.active = False
    
    async def connect(self) -> bool:
        """Establish persistent connection"""
        global CURRENT_CONNECT_IP, CURRENT_FAKE_SNI, current_status
        
        async with self.lock:
            if self.connected and self.outgoing_sock:
                return True
            
            current_status = "PERSISTENT_CONNECTING"
            print_status("Establishing persistent connection...", "info")
            
            # Try SNI-IP pairs
            for pair in SNI_IP_PAIRS:
                if not self.active:
                    break
                    
                sni = pair["sni"].encode()
                ip = pair["ip"]
                
                print_connection_status("connecting", ip=ip, sni=pair["sni"])
                
                if DATA_MODE == "tls":
                    fake_data = ClientHelloMaker.get_client_hello_with(
                        os.urandom(32), 
                        os.urandom(32), 
                        sni,
                        os.urandom(32)
                    )
                else:
                    continue
                
                # Try connection
                for attempt in range(RETRY_COUNT):
                    if not self.active:
                        break
                    
                    try:
                        loop = asyncio.get_running_loop()
                        
                        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        outgoing_sock.setblocking(False)
                        outgoing_sock.bind((INTERFACE_IPV4, 0))
                        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
                        
                        src_port = outgoing_sock.getsockname()[1]
                        fake_inj_conn = FakeInjectiveConnection(
                            outgoing_sock, INTERFACE_IPV4, ip, src_port, CONNECT_PORT,
                            fake_data, BYPASS_METHOD, None
                        )
                        fake_injective_connections[fake_inj_conn.id] = fake_inj_conn
                        
                        await asyncio.wait_for(
                            loop.sock_connect(outgoing_sock, (ip, CONNECT_PORT)),
                            CONNECTION_TIMEOUT
                        )
                        
                        print_status(f"TCP connected to {ip}", "info")
                        
                        if BYPASS_METHOD == "wrong_seq":
                            try:
                                await asyncio.wait_for(
                                    fake_inj_conn.t2a_event.wait(), 
                                    CONNECTION_TIMEOUT
                                )
                                
                                if fake_inj_conn.t2a_msg == "fake_data_ack_recv":
                                    self.outgoing_sock = outgoing_sock
                                    self.fake_injective_conn = fake_inj_conn
                                    self.current_ip = ip
                                    self.current_sni = sni.decode()
                                    self.connected = True
                                    
                                    CURRENT_CONNECT_IP = ip
                                    CURRENT_FAKE_SNI = sni.decode()
                                    current_status = "PERSISTENT_CONNECTED"
                                    
                                    print_connection_status("connected", ip=ip, sni=sni.decode())
                                    print_status("Persistent connection established!", "success")
                                    
                                    fake_inj_conn.monitor = False
                                    if fake_inj_conn.id in fake_injective_connections:
                                        del fake_injective_connections[fake_inj_conn.id]
                                    
                                    return True
                            except asyncio.TimeoutError:
                                pass
                    except Exception as e:
                        print_status(f"Error: {str(e)[:40]}...", "error", show_ip=False)
                    
                    # Cleanup failed attempt
                    fake_inj_conn.monitor = False
                    if fake_inj_conn.id in fake_injective_connections:
                        del fake_injective_connections[fake_inj_conn.id]
                    try:
                        outgoing_sock.close()
                    except:
                        pass
                    
                    if attempt < RETRY_COUNT - 1:
                        await asyncio.sleep(RETRY_DELAY)
            
            # Try fallbacks
            for sni in FALLBACK_SNIS:
                if not self.active or self.connected:
                    break
                    
                for ip in FALLBACK_IPS:
                    if not self.active or self.connected:
                        break
                    
                    sni_bytes = sni.encode() if isinstance(sni, str) else sni
                    
                    if DATA_MODE == "tls":
                        fake_data = ClientHelloMaker.get_client_hello_with(
                            os.urandom(32), 
                            os.urandom(32), 
                            sni_bytes,
                            os.urandom(32)
                        )
                    else:
                        continue
                    
                    for attempt in range(RETRY_COUNT):
                        if not self.active or self.connected:
                            break
                        
                        try:
                            loop = asyncio.get_running_loop()
                            
                            outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            outgoing_sock.setblocking(False)
                            outgoing_sock.bind((INTERFACE_IPV4, 0))
                            outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
                            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
                            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
                            
                            src_port = outgoing_sock.getsockname()[1]
                            fake_inj_conn = FakeInjectiveConnection(
                                outgoing_sock, INTERFACE_IPV4, ip, src_port, CONNECT_PORT,
                                fake_data, BYPASS_METHOD, None
                            )
                            fake_injective_connections[fake_inj_conn.id] = fake_inj_conn
                            
                            await asyncio.wait_for(
                                loop.sock_connect(outgoing_sock, (ip, CONNECT_PORT)),
                                CONNECTION_TIMEOUT
                            )
                            
                            if BYPASS_METHOD == "wrong_seq":
                                try:
                                    await asyncio.wait_for(
                                        fake_inj_conn.t2a_event.wait(), 
                                        CONNECTION_TIMEOUT
                                    )
                                    
                                    if fake_inj_conn.t2a_msg == "fake_data_ack_recv":
                                        self.outgoing_sock = outgoing_sock
                                        self.fake_injective_conn = fake_inj_conn
                                        self.current_ip = ip
                                        self.current_sni = sni_bytes.decode() if isinstance(sni_bytes, bytes) else sni
                                        self.connected = True
                                        
                                        CURRENT_CONNECT_IP = ip
                                        CURRENT_FAKE_SNI = self.current_sni
                                        current_status = "PERSISTENT_CONNECTED"
                                        
                                        print_connection_status("connected", ip=ip, sni=self.current_sni)
                                        print_status("Persistent connection established!", "success")
                                        
                                        fake_inj_conn.monitor = False
                                        if fake_inj_conn.id in fake_injective_connections:
                                            del fake_injective_connections[fake_inj_conn.id]
                                        
                                        return True
                                except asyncio.TimeoutError:
                                    pass
                        except Exception as e:
                            pass
                        
                        fake_inj_conn.monitor = False
                        if fake_inj_conn.id in fake_injective_connections:
                            del fake_injective_connections[fake_inj_conn.id]
                        try:
                            outgoing_sock.close()
                        except:
                            pass
                        
                        if attempt < RETRY_COUNT - 1:
                            await asyncio.sleep(RETRY_DELAY)
            
            current_status = "PERSISTENT_FAILED"
            print_status("Failed to establish persistent connection", "error")
            return False
    
    async def reconnect_loop(self):
        """Reconnect loop for persistent mode"""
        while self.active:
            await self.connect()
            if self.connected:
                # Wait until connection drops
                while self.active and self.connected:
                    await asyncio.sleep(1)
                    # Check if socket is still valid
                    if self.outgoing_sock:
                        try:
                            # Test if socket is still connected
                            self.outgoing_sock.getpeername()
                        except:
                            self.connected = False
                            print_status("Persistent connection lost, reconnecting...", "warning")
                            break
            else:
                # Wait before retry
                await asyncio.sleep(PERSISTENT_RECONNECT_DELAY)
    
    def start(self):
        """Start persistent connection manager"""
        self.active = True
        self.reconnect_task = asyncio.create_task(self.reconnect_loop())
    
    async def stop(self):
        """Stop persistent connection manager"""
        self.active = False
        if self.reconnect_task:
            self.reconnect_task.cancel()
            try:
                await self.reconnect_task
            except:
                pass
        if self.outgoing_sock:
            try:
                self.outgoing_sock.close()
            except:
                pass
        self.connected = False
    
    def get_connection(self):
        """Get current persistent connection socket"""
        if self.connected and self.outgoing_sock:
            return self.outgoing_sock, self.current_ip, self.current_sni
        return None, None, None


# Global persistent connection manager
persistent_manager = PersistentConnectionManager()

# Mode switching flag
mode_switch_requested = False


def keyboard_listener():
    """Listen for keyboard input to switch modes"""
    import msvcrt
    import time
    while not shutdown_event.is_set():
        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key == b'm' or key == b'M':
                request_mode_switch()
        time.sleep(0.1)


def request_mode_switch():
    """Request to switch connection mode"""
    global mode_switch_requested
    mode_switch_requested = True


async def handle_mode_switch():
    """Handle mode switching request"""
    global CONNECTION_MODE, mode_switch_requested
    
    if not mode_switch_requested:
        return
    
    mode_switch_requested = False
    
    old_mode = CONNECTION_MODE
    new_mode = "persistent" if old_mode == "on_demand" else "on_demand"
    
    print_status(f"Switching mode from {old_mode} to {new_mode}...", "info")
    
    # Stop current mode
    if old_mode == "persistent":
        await persistent_manager.stop()
    
    # Switch mode
    CONNECTION_MODE = new_mode
    
    # Start new mode
    if new_mode == "persistent":
        persistent_manager.start()
        print_status(f"Mode switched to PERSISTENT", "success")
    else:
        print_status(f"Mode switched to ON-DEMAND", "success")
    
    # Refresh UI
    print_header()
    print_status_bar()
    print_log_area()


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                          first_prefix_data: bytes):
    """Relay data between two sockets with improved error handling"""
    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(sock_1, RELAY_BUFFER_SIZE)
                if not data:
                    logger.debug("EOF received, closing connection")
                    raise ValueError("eof")
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                sent_len = await loop.sock_sendall(sock_2, data)
                if sent_len != len(data):
                    logger.warning(f"Incomplete send: {sent_len}/{len(data)} bytes")
                    raise ValueError("incomplete send")
            except asyncio.CancelledError:
                logger.debug("Relay task cancelled")
                raise
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.debug(f"Connection error in relay: {e}")
                raise ValueError(f"connection error: {e}")
            except Exception as e:
                logger.debug(f"Relay loop exception: {e}")
                raise
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.error(f"Relay main loop error: {traceback.format_exc()}")
    finally:
        try:
            sock_1.close()
        except:
            pass
        try:
            sock_2.close()
        except:
            pass
        try:
            peer_task.cancel()
        except:
            pass


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    """Handle incoming connection with retry mechanism and improved error handling"""
    global active_connections, CURRENT_CONNECT_IP, CURRENT_FAKE_SNI, total_snis_tested, current_status
    
    client_addr = f"{incoming_remote_addr[0]}:{incoming_remote_addr[1]}"
    
    with connection_lock:
        active_connections += 1
    
    current_status = "CONNECTING"
    total_snis_tested = 0
    
    print_status(f"New connection from {client_addr}", "info")
    print_connection_status("waiting", sni="selecting...")
    
    try:
        loop = asyncio.get_running_loop()
        
        # Try different IP/SNI combinations
        connection_success = False
        last_error = None
        outgoing_sock = None
        fake_injective_conn = None
        
        # PERSISTENT MODE: Use pre-established connection
        if CONNECTION_MODE == "persistent":
            # Wait for persistent connection to be ready
            max_wait = 30
            waited = 0
            while not persistent_manager.connected and waited < max_wait:
                await asyncio.sleep(0.5)
                waited += 0.5
            
            if persistent_manager.connected:
                # Get the persistent connection
                out_sock, conn_ip, conn_sni = persistent_manager.get_connection()
                if out_sock:
                    # Create a new socket for this client (duplicate the connection)
                    try:
                        # For persistent mode, we create a new connection to the same IP
                        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        outgoing_sock.setblocking(False)
                        outgoing_sock.bind((INTERFACE_IPV4, 0))
                        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
                        
                        await asyncio.wait_for(
                            loop.sock_connect(outgoing_sock, (conn_ip, CONNECT_PORT)),
                            CONNECTION_TIMEOUT
                        )
                        
                        CURRENT_CONNECT_IP = conn_ip
                        CURRENT_FAKE_SNI = conn_sni
                        connection_success = True
                        current_status = "CONNECTED"
                        print_connection_status("connected", ip=conn_ip, sni=conn_sni)
                        print_status(f"Client {client_addr} connected via persistent", "success")
                    except Exception as e:
                        print_status(f"Failed to use persistent connection: {e}", "error")
                        # Fall through to on-demand mode
                        connection_success = False
            else:
                print_status("Persistent connection not available, falling back to on-demand", "warning")
        
        # ON-DEMAND MODE: Create new connection for each client
        if not connection_success and CONNECTION_MODE == "on_demand":
            # First, try SNI-IP pairs from config
            for pair in SNI_IP_PAIRS:
                if shutdown_event.is_set():
                    break
                
                total_snis_tested += 1
                sni = pair["sni"].encode()
                ip = pair["ip"]
                
                print_connection_status("connecting", ip=ip, sni=pair["sni"])
            
            # Generate fake TLS Client Hello
            if DATA_MODE == "tls":
                fake_data = ClientHelloMaker.get_client_hello_with(
                    os.urandom(32), 
                    os.urandom(32), 
                    sni,
                    os.urandom(32)
                )
            else:
                logger.error("Invalid data mode!")
                incoming_sock.close()
                return
            
            # Retry loop for this IP/SNI
            for attempt in range(RETRY_COUNT):
                if shutdown_event.is_set():
                    break
                
                print_status(f"Attempt {attempt + 1}/{RETRY_COUNT} for {ip}:{CONNECT_PORT}", "trying")
                
                # Create outgoing socket
                outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                outgoing_sock.setblocking(False)
                outgoing_sock.bind((INTERFACE_IPV4, 0))
                outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
                outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
                outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
                
                src_port = outgoing_sock.getsockname()[1]
                fake_injective_conn = FakeInjectiveConnection(
                    outgoing_sock, INTERFACE_IPV4, ip, src_port, CONNECT_PORT,
                    fake_data, BYPASS_METHOD, incoming_sock
                )
                fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
                
                try:
                    # Connect with timeout
                    await asyncio.wait_for(
                        loop.sock_connect(outgoing_sock, (ip, CONNECT_PORT)),
                        CONNECTION_TIMEOUT
                    )
                    
                    print_status(f"TCP connected to {ip}", "info")
                    
                    # Wait for bypass handshake
                    if BYPASS_METHOD == "wrong_seq":
                        try:
                            await asyncio.wait_for(
                                fake_injective_conn.t2a_event.wait(), 
                                CONNECTION_TIMEOUT
                            )
                            
                            if fake_injective_conn.t2a_msg == "unexpected_close":
                                raise ValueError("unexpected close during handshake")
                            elif fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                                # Success!
                                CURRENT_CONNECT_IP = ip
                                CURRENT_FAKE_SNI = sni.decode()
                                connection_success = True
                                break
                            else:
                                raise ValueError(f"unknown t2a msg: {fake_injective_conn.t2a_msg}")
                        except asyncio.TimeoutError:
                            raise ValueError("bypass handshake timeout")
                    else:
                        raise ValueError(f"unknown bypass method: {BYPASS_METHOD}")
                        
                except Exception as e:
                    last_error = e
                    print_connection_status("failed", ip=ip)
                    print_status(f"خطا: {str(e)[:50]}...", "error", show_ip=False)
                    
                    # Cleanup
                    fake_injective_conn.monitor = False
                    if fake_injective_conn.id in fake_injective_connections:
                        del fake_injective_connections[fake_injective_conn.id]
                    try:
                        outgoing_sock.close()
                    except:
                        pass
                    outgoing_sock = None
                    
                    # Wait before retry
                    if attempt < RETRY_COUNT - 1:
                        await asyncio.sleep(RETRY_DELAY)
            
            # End of SNI-IP pairs loop
        
        # If SNI-IP pairs failed, try fallbacks
        if not connection_success and (FALLBACK_IPS or FALLBACK_SNIS):
            print_status("Primary list failed, trying fallbacks...", "warning")
            print_connection_status("fallback", sni="trying...")
            
            for sni in FALLBACK_SNIS:
                if shutdown_event.is_set() or connection_success:
                    break
                    
                for ip in FALLBACK_IPS:
                    if shutdown_event.is_set() or connection_success:
                        break
                    
                    total_snis_tested += 1
                    sni_str = sni if isinstance(sni, str) else sni.decode()
                    print_connection_status("connecting", ip=ip, sni=sni_str)
                    
                    sni_bytes = sni.encode() if isinstance(sni, str) else sni
                    
                    if DATA_MODE == "tls":
                        fake_data = ClientHelloMaker.get_client_hello_with(
                            os.urandom(32), 
                            os.urandom(32), 
                            sni_bytes,
                            os.urandom(32)
                        )
                    else:
                        continue
                    
                    for attempt in range(RETRY_COUNT):
                        if shutdown_event.is_set() or connection_success:
                            break
                        
                        print_status(f"Attempt {attempt + 1}/{RETRY_COUNT} for {ip}:{CONNECT_PORT}", "trying")
                        
                        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        outgoing_sock.setblocking(False)
                        outgoing_sock.bind((INTERFACE_IPV4, 0))
                        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
                        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
                        
                        src_port = outgoing_sock.getsockname()[1]
                        fake_injective_conn = FakeInjectiveConnection(
                            outgoing_sock, INTERFACE_IPV4, ip, src_port, CONNECT_PORT,
                            fake_data, BYPASS_METHOD, incoming_sock
                        )
                        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
                        
                        try:
                            await asyncio.wait_for(
                                loop.sock_connect(outgoing_sock, (ip, CONNECT_PORT)),
                                CONNECTION_TIMEOUT
                            )
                            
                            print_status(f"TCP connected to {ip}", "info")
                            
                            if BYPASS_METHOD == "wrong_seq":
                                try:
                                    await asyncio.wait_for(
                                        fake_injective_conn.t2a_event.wait(), 
                                        CONNECTION_TIMEOUT
                                    )
                                    
                                    if fake_injective_conn.t2a_msg == "unexpected_close":
                                        raise ValueError("unexpected close during handshake")
                                    elif fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                                        CURRENT_CONNECT_IP = ip
                                        CURRENT_FAKE_SNI = sni_bytes.decode() if isinstance(sni_bytes, bytes) else sni
                                        connection_success = True
                                        break
                                    else:
                                        raise ValueError(f"unknown t2a msg: {fake_injective_conn.t2a_msg}")
                                except asyncio.TimeoutError:
                                    raise ValueError("bypass handshake timeout")
                        except Exception as e:
                            last_error = e
                            print_connection_status("failed", ip=ip)
                            print_status(f"Error: {str(e)[:50]}...", "error", show_ip=False)
                            
                            fake_injective_conn.monitor = False
                            if fake_injective_conn.id in fake_injective_connections:
                                del fake_injective_connections[fake_injective_conn.id]
                            try:
                                outgoing_sock.close()
                            except:
                                pass
                            outgoing_sock = None
                            
                            if attempt < RETRY_COUNT - 1:
                                await asyncio.sleep(RETRY_DELAY)
        
        if not connection_success:
            current_status = "FAILED"
            print_status(f"Connection failed: {last_error}", "error")
            print_connection_status("failed", sni="no combination worked")
            incoming_sock.close()
            return

        # Connection successful!
        current_status = "CONNECTED"
        print_connection_status("connected", ip=CURRENT_CONNECT_IP, sni=CURRENT_FAKE_SNI)
        print_status(f"Client {client_addr} connected", "success")
        
        # Cleanup connection tracking
        fake_injective_conn.monitor = False
        if fake_injective_conn.id in fake_injective_connections:
            del fake_injective_connections[fake_injective_conn.id]

        # Start relay
        logger.debug("Starting data relay")
        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b"")
        )
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except asyncio.CancelledError:
        logger.debug("Handle task cancelled")
    except Exception:
        logger.error(f"Handle error: {traceback.format_exc()}")
    finally:
        with connection_lock:
            active_connections -= 1


async def main():
    """Main async loop with graceful shutdown support"""
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
    mother_sock.listen()
    
    # Print header
    print_header()
    print_status_bar()
    print_log_area()
    
    logger.info(f"Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    logger.info(f"SNI-IP Pairs: {len(SNI_IP_PAIRS)} pairs loaded")
    logger.info(f"Fallback IPs: {len(FALLBACK_IPS)}, SNIs: {len(FALLBACK_SNIS)}")
    logger.info(f"Interface IP: {INTERFACE_IPV4}")
    logger.info(f"Connection Mode: {CONNECTION_MODE}")
    
    # Start persistent connection manager if in persistent mode
    if CONNECTION_MODE == "persistent":
        logger.info("Starting persistent connection manager...")
        persistent_manager.start()
        print_status("Persistent connection manager started", "info")
    
    # Start keyboard listener for mode switching
    if os.name == 'nt':  # Windows
        threading.Thread(target=keyboard_listener, daemon=True).start()
    
    loop = asyncio.get_running_loop()
    
    # Setup non-blocking stdin for mode switching
    if CONNECTION_MODE == "persistent":
        # In persistent mode, allow mode switching via keyboard
        print_status("Press 'M' to switch mode, Ctrl+C to exit", "info")
    
    while not shutdown_event.is_set():
        try:
            # Check for mode switch request
            if mode_switch_requested:
                await handle_mode_switch()
            
            # Use wait_for to allow checking shutdown event
            incoming_sock, addr = await asyncio.wait_for(
                loop.sock_accept(mother_sock),
                timeout=1.0
            )
            incoming_sock.setblocking(False)
            incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
            asyncio.create_task(handle(incoming_sock, addr))
        except asyncio.TimeoutError:
            continue
        except OSError as e:
            # Network errors are common - just log and continue
            if not shutdown_event.is_set():
                logger.debug(f"Accept error: {e}")
            continue  # Continue instead of breaking
    
    # Graceful shutdown
    logger.info("Shutting down...")
    
    # Stop persistent connection manager if running
    if CONNECTION_MODE == "persistent":
        await persistent_manager.stop()
    
    mother_sock.close()
    
    # Wait for active connections
    timeout = 10
    while active_connections > 0 and timeout > 0:
        logger.info(f"Waiting for {active_connections} active connection(s)...")
        await asyncio.sleep(1)
        timeout -= 1
    
    logger.info("Shutdown complete")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()


def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    if hasattr(signal, 'SIGINT'):
        signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)


if __name__ == "__main__":
    # Setup signal handlers
    setup_signal_handlers()
    
    # Create WinDivert filter (monitor all IPs from SNI-IP pairs + fallbacks)
    all_ips = set()
    for pair in SNI_IP_PAIRS:
        all_ips.add(pair["ip"])
    for ip in FALLBACK_IPS:
        all_ips.add(ip)
    
    ip_filters = " or ".join([f"(ip.DstAddr == {ip})" for ip in all_ips])
    w_filter = f"tcp and (ip.SrcAddr == {INTERFACE_IPV4} and ({ip_filters}))"
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    
    # Print header (already done in main())
    print("\nPress Ctrl+C to stop gracefully\n")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)
