"""
Configuration management for SNI-Spoofing proxy.
Supports CLI arguments, config files, and environment variables.
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ProxyConfig:
    """Main configuration for the SNI-Spoofing proxy."""
    
    # Local proxy settings
    local_host: str = "127.0.0.1"
    local_port: int = 1080
    
    # Remote connection settings
    remote_host: Optional[str] = None
    remote_port: int = 443
    
    # SNI configuration
    sni: str = "www.cloudflare.com"
    sni_list: list[str] = field(default_factory=lambda: [
        "www.cloudflare.com",
        "dash.cloudflare.com",
        "api.cloudflare.com",
        "blog.cloudflare.com",
        "developers.cloudflare.com",
    ])
    sni_file: Optional[str] = None
    
    # IP management
    cf_ip_file: Optional[str] = None
    cf_ips: list[str] = field(default_factory=lambda: [
        "104.16.0.0/12",
        "172.64.0.0/12",
        "172.65.0.0/12",
        "172.66.0.0/12",
        "172.67.0.0/12",
        "172.68.0.0/12",
        "172.69.0.0/12",
        "172.70.0.0/12",
        "172.71.0.0/12",
        "188.114.96.0/20",
        "188.114.97.0/20",
        "188.114.98.0/20",
        "188.114.99.0/20",
    ])
    
    # Connection pool settings
    pool_size: int = 5
    max_retries: int = 5
    
    # Timeout settings (seconds)
    connect_timeout: int = 10
    read_timeout: int = 300
    write_timeout: int = 30
    
    # Buffer settings
    buffer_size: int = 32768
    
    # TCP settings
    tcp_nodelay: bool = True
    keepalive: bool = True
    keepalive_idle: int = 60
    keepalive_interval: int = 10
    keepalive_count: int = 5
    
    # TLS settings
    tls_version: str = "1.3"
    verify_ssl: bool = True
    alpn: list[str] = field(default_factory=lambda: ["h2", "http/1.1"])
    
    # Retry settings
    retry_delays: list[float] = field(default_factory=lambda: [1, 2, 4, 8, 15])
    
    # Health monitoring
    health_check_interval: int = 30
    health_check_timeout: int = 5
    
    # Circuit breaker
    circuit_breaker_threshold: int = 3
    circuit_breaker_window: int = 60
    circuit_breaker_cooldown: int = 300
    
    # Logging
    verbose: int = 0  # 0=INFO, 1=DEBUG, 2=VERBOSE, 3=TRACE
    log_file: Optional[str] = None
    
    # Special modes
    test_mode: bool = False
    benchmark_mode: bool = False
    
    # Bypass method (Windows-specific)
    bypass_method: str = "wrong_seq"
    
    # Connection mode
    connection_mode: str = "on_demand"  # "on_demand" or "persistent"
    persistent_reconnect_delay: int = 5
    
    def __post_init__(self):
        """Load SNI list from file if specified."""
        if self.sni_file and os.path.exists(self.sni_file):
            with open(self.sni_file, 'r') as f:
                self.sni_list = [line.strip() for line in f if line.strip()]
        
        # Load Cloudflare IPs from file if specified
        if self.cf_ip_file and os.path.exists(self.cf_ip_file):
            with open(self.cf_ip_file, 'r') as f:
                self.cf_ips = [line.strip() for line in f if line.strip()]
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "local_host": self.local_host,
            "local_port": self.local_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "sni": self.sni,
            "sni_list": self.sni_list,
            "pool_size": self.pool_size,
            "max_retries": self.max_retries,
            "connect_timeout": self.connect_timeout,
            "read_timeout": self.read_timeout,
            "write_timeout": self.write_timeout,
            "buffer_size": self.buffer_size,
            "verbose": self.verbose,
            "bypass_method": self.bypass_method,
            "connection_mode": self.connection_mode,
        }


def load_config_from_file(config_path: str) -> dict:
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config file not found: {config_path}")
        return {}
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config file: {e}")
        return {}


def load_config_from_env() -> dict:
    """Load configuration from environment variables."""
    config = {}
    
    # Map environment variables to config keys
    env_mappings = {
        "SNI_LOCAL_HOST": "local_host",
        "SNI_LOCAL_PORT": "local_port",
        "SNI_REMOTE_HOST": "remote_host",
        "SNI_REMOTE_PORT": "remote_port",
        "SNI_SNI": "sni",
        "SNI_POOL_SIZE": "pool_size",
        "SNI_MAX_RETRIES": "max_retries",
        "SNI_CONNECT_TIMEOUT": "connect_timeout",
        "SNI_READ_TIMEOUT": "read_timeout",
        "SNI_WRITE_TIMEOUT": "write_timeout",
        "SNI_BUFFER_SIZE": "buffer_size",
        "SNI_VERBOSE": "verbose",
    }
    
    for env_key, config_key in env_mappings.items():
        value = os.environ.get(env_key)
        if value is not None:
            # Convert to appropriate type
            if config_key in ("local_port", "remote_port", "pool_size", "max_retries",
                            "connect_timeout", "read_timeout", "write_timeout", "buffer_size", "verbose"):
                try:
                    config[config_key] = int(value)
                except ValueError:
                    pass
            else:
                config[config_key] = value
    
    return config


def parse_arguments() -> ProxyConfig:
    """Parse command-line arguments and merge with config file and environment variables."""
    parser = argparse.ArgumentParser(
        description="SNI-Spoofing Proxy - DPI Bypasser for V2Ray behind Cloudflare",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --local-port 1080 --sni www.cloudflare.com
  %(prog)s --config config.json
  %(prog)s --benchmark
  %(prog)s -vv --test-mode
        """
    )
    
    # Local proxy settings
    parser.add_argument(
        "--local-host", 
        default="127.0.0.1", 
        help="Local bind address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--local-port", 
        type=int, 
        default=1080, 
        help="Local listen port (default: 1080)"
    )
    
    # Remote connection settings
    parser.add_argument(
        "--remote-host",
        default=None,
        help="Remote Cloudflare IP (auto-detect if not specified)"
    )
    parser.add_argument(
        "--remote-port",
        type=int,
        default=443,
        help="Remote port (default: 443)"
    )
    
    # SNI configuration
    parser.add_argument(
        "--sni",
        default="www.cloudflare.com",
        help="SNI hostname (default: www.cloudflare.com)"
    )
    parser.add_argument(
        "--sni-file",
        default=None,
        help="File containing list of SNIs (one per line)"
    )
    
    # IP management
    parser.add_argument(
        "--cf-ip-file",
        default=None,
        help="File containing list of Cloudflare IPs (one per line)"
    )
    
    # Connection pool settings
    parser.add_argument(
        "--pool-size",
        type=int,
        default=5,
        help="Connection pool size (default: 5)"
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=5,
        help="Maximum retry attempts (default: 5)"
    )
    
    # Timeout settings
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        dest="connect_timeout",
        help="Connection timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--read-timeout",
        type=int,
        default=300,
        help="Read timeout in seconds (default: 300)"
    )
    parser.add_argument(
        "--write-timeout",
        type=int,
        default=30,
        help="Write timeout in seconds (default: 30)"
    )
    
    # Buffer settings
    parser.add_argument(
        "--buffer-size",
        type=int,
        default=32768,
        help="Buffer size in bytes (default: 32768)"
    )
    
    # TLS settings
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    parser.add_argument(
        "--alpn",
        default="h2,http/1.1",
        help="ALPN protocols (default: h2,http/1.1)"
    )
    
    # Logging
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)"
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Log to file instead of stdout"
    )
    
    # Special modes
    parser.add_argument(
        "--test-mode",
        action="store_true",
        help="Test connectivity and exit"
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Benchmark Cloudflare IPs and exit"
    )
    
    # Config file
    parser.add_argument(
        "--config-file",
        default=None,
        help="Path to JSON configuration file"
    )
    
    # Bypass method
    parser.add_argument(
        "--bypass-method",
        default="wrong_seq",
        choices=["wrong_seq", "wrong_checksum"],
        help="DPI bypass method (default: wrong_seq)"
    )
    
    # Connection mode
    parser.add_argument(
        "--connection-mode",
        default="on_demand",
        choices=["on_demand", "persistent"],
        help="Connection mode (default: on_demand)"
    )
    
    args = parser.parse_args()
    
    # Priority: CLI args > config file > environment variables > defaults
    config = {}
    
    # Start with defaults
    config_obj = ProxyConfig()
    config = config_obj.to_dict()
    
    # Apply environment variables (lower priority than CLI)
    env_config = load_config_from_env()
    config.update(env_config)
    
    # Apply config file (higher priority than environment)
    if args.config_file:
        file_config = load_config_from_file(args.config_file)
        config.update(file_config)
    
    # Apply CLI arguments (highest priority)
    cli_config = {}
    for key, value in vars(args).items():
        if value is not None and key not in ("config_file",):
            # Map CLI argument to config key
            if key == "local_host":
                cli_config["local_host"] = value
            elif key == "local_port":
                cli_config["local_port"] = value
            elif key == "remote_host":
                cli_config["remote_host"] = value
            elif key == "remote_port":
                cli_config["remote_port"] = value
            elif key == "sni":
                cli_config["sni"] = value
            elif key == "sni_file":
                cli_config["sni_file"] = value
            elif key == "cf_ip_file":
                cli_config["cf_ip_file"] = value
            elif key == "pool_size":
                cli_config["pool_size"] = value
            elif key == "max_retries":
                cli_config["max_retries"] = value
            elif key == "connect_timeout":
                cli_config["connect_timeout"] = value
            elif key == "read_timeout":
                cli_config["read_timeout"] = value
            elif key == "write_timeout":
                cli_config["write_timeout"] = value
            elif key == "buffer_size":
                cli_config["buffer_size"] = value
            elif key == "verbose":
                cli_config["verbose"] = value
            elif key == "log_file":
                cli_config["log_file"] = value
            elif key == "test_mode":
                cli_config["test_mode"] = value
            elif key == "benchmark_mode":
                cli_config["benchmark_mode"] = value
            elif key == "bypass_method":
                cli_config["bypass_method"] = value
            elif key == "connection_mode":
                cli_config["connection_mode"] = value
            elif key == "no_verify":
                cli_config["verify_ssl"] = not value
            elif key == "alpn":
                cli_config["alpn"] = value.split(",")
    
    config.update(cli_config)
    
    # Create final config object
    final_config = ProxyConfig(**config)
    
    return final_config


def create_default_config_file(path: str = "config.json"):
    """Create a default configuration file."""
    default_config = {
        "local_host": "127.0.0.1",
        "local_port": 1080,
        "remote_port": 443,
        "sni": "www.cloudflare.com",
        "sni_list": [
            "www.cloudflare.com",
            "dash.cloudflare.com",
            "api.cloudflare.com",
            "blog.cloudflare.com",
            "developers.cloudflare.com",
        ],
        "pool_size": 5,
        "max_retries": 5,
        "connect_timeout": 10,
        "read_timeout": 300,
        "write_timeout": 30,
        "buffer_size": 32768,
        "verbose": 0,
        "bypass_method": "wrong_seq",
        "connection_mode": "on_demand",
        "health_check_interval": 30,
    }
    
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(default_config, f, indent=2)
    
    print(f"Default config created: {path}")