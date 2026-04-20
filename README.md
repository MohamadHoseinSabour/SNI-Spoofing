پرامت مرحله بعدی :


# Master Prompt: SNI-Spoofing Advanced Rewrite with IP+SNI Combo Testing

## Project Overview
بازنویسی کامل پروژه SNI-Spoofing با قابلیت تست هوشمند ترکیبات IP+SNI برای عبور از فیلترینگ پیشرفته.

## Core Requirements

### 1. Architecture
- **زبان:** Python 3.8+
- **ساختار:** Async/await با asyncio
- **فایل‌های اصلی:**
  - `sni_proxy.py` - فایل اصلی
  - `cloudflare_ips.txt` - لیست IPهای Cloudflare
  - `sni_list.txt` - لیست SNIهای مختلف
  - `working_combos.json` - کش ترکیبات موفق
  - `config.yaml` - تنظیمات

### 2. IP+SNI Combo Testing Strategy

#### 2.1 مدیریت لیست‌ها
```python
# فرمت cloudflare_ips.txt (هر خط یک IP)
104.16.0.1
104.18.0.1
162.159.0.1

# فرمت sni_list.txt (هر خط یک SNI)
www.cloudflare.com
cloudflare.com
workers.dev
cdn.cloudflare.net

#### 2.2 تست ماتریسی (Cartesian Product)
- تولید همه ترکیبات ممکن IP×SNI
- تست موازی با `asyncio.gather()` و محدودیت همزمانی (مثلاً 50 تا)
- Timeout کوتاه برای هر تست (2-3 ثانیه)
- اولین ترکیب موفق → استفاده فوری

python
async def test_combo(ip: str, sni: str, timeout: float = 3.0) -> Optional[ComboResult]:
"""
تست یک ترکیب IP+SNI
Return: ComboResult(ip, sni, latency, success) یا None
"""
pass

#### 2.3 کش کردن ترکیبات موفق
json
// فرمت working_combos.json
{
  "combos": [
{
"ip": "104.16.0.1",
"sni": "www.cloudflare.com",
"last_success": "2026-04-20T10:30:00Z",
"avg_latency_ms": 45,
"success_rate": 0.95,
"total_tests": 100
}
  ],
  "last_updated": "2026-04-20T10:30:00Z"
}

**الزامات کش:**
- Sort by: success_rate DESC, avg_latency ASC
- در startup اول کمبوهای cached رو تست کن
- اگه کمبوی cached fail شد، حذفش کن و به بعدی برو
- هر 5 دقیقه کش رو به‌روز کن

#### 2.4 چرخش خودکار (Auto Rotation)
python
class ComboRotator:
async def get_next_working_combo(self) -> Tuple[str, str]:
"""
1. اول cached combos رو امتحان کن
2. اگه همه fail شدن، full scan کن
3. اگه هیچی پیدا نشد، exponential backoff retry
"""
pass

async def health_check_loop(self):
"""
هر 30 ثانیه کمبوی فعلی رو چک کن
اگه fail شد، خودکار rotate کن
"""
pass

### 3. Connection Management

#### 3.1 Connection Pool
python
class ConnectionPool:
def __init__(self, max_size: int = 10):
self.pool: List[TLSConnection] = []
self.current_combo: Tuple[str, str] = None

async def get_connection(self) -> TLSConnection:
"""
اگه connection سالم داریم، بده
اگه نه، با کمبوی جدید بساز
"""
pass

async def rotate_combo(self):
"""
همه connectionهای قدیمی رو ببند
با کمبوی جدید pool رو rebuild کن
"""
pass

#### 3.2 TLS Connection با SNI Spoofing
python
async def create_tls_connection(ip: str, sni: str, port: int = 443) -> ssl.SSLSocket:
"""
1. TCP socket به IP
2. TLS handshake با SNI جعلی
3. TCP KeepAlive فعال
4. Socket options: TCP_NODELAY, SO_KEEPALIVE
"""
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
# اگه ممکنه از utls برای fingerprint spoofing استفاده کن
pass

### 4. Proxy Core Logic

python
class SNIProxy:
def __init__(self, local_port: int, buffer_size: int = 32768):
self.local_port = local_port
self.buffer_size = buffer_size
self.combo_rotator = ComboRotator()
self.connection_pool = ConnectionPool()

async def handle_client(self, reader, writer):
"""
1. از pool یه connection بگیر
2. داده‌های client رو forward کن
3. اگه connection fail شد، rotate و retry
"""
pass

async def forward_data(self, src, dst, direction: str):
"""
انتقال داده با buffer بزرگ (32KB)
Error handling و reconnect
"""
pass

### 5. Benchmark Mode

python
async def benchmark_mode(ips: List[str], snis: List[str], output_file: str):
"""
تست همه کمبوها و خروجی:

RANK | IP            | SN
:::writing

Master Prompt for Copilot – Advanced Rewrite of SNI-Spoofing with Intelligent IP+SNI Discovery

Goal

Rewrite and significantly improve the project so it can automatically discover working Cloudflare IP + SNI combinations and maintain a stable TLS tunnel even when many IPs or SNIs are blocked.

Key Idea

Instead of using a single IP or single SNI, the program must dynamically test many IP+SNI combinations, cache the working ones, and automatically rotate between them when connections fail.

Language and Core Stack

Python 3.9+
asyncio for concurrency
ssl for TLS
optional: uvloop for performance
optional: aiofiles for async file operations
Project Structure

sni-spoof/

├── sni_proxy.py

├── combo_manager.py

├── connection_pool.py

├── benchmark.py

├── config.yaml

├── cloudflare_ips.txt

├── sni_list.txt

└── working_combos.json

Input Files

cloudflare_ips.txt

Each line contains a Cloudflare IP.

Example:

104.16.0.1

104.18.1.10

162.159.36.1

172.67.200.10

sni_list.txt

Each line contains an SNI hostname.

Example:

www.cloudflare.com

cloudflare.com

cdnjs.cloudflare.com

workers.dev

ajax.cloudflare.com

Core Feature 1 — Cartesian Combo Testing

The program must generate all combinations of:

IP × SNI

Example:

50 IPs × 20 SNIs = 1000 combos.

Each combo should be tested with a short TLS handshake.

Pseudo logic:

for ip in ip_list:

for sni in sni_list:

combos.append((ip, sni))

Testing must be done concurrently using asyncio with a semaphore limit (for example 50 simultaneous tests).

Function:

async def test_combo(ip: str, sni: str, timeout: float = 3.0):

open TCP connection to ip:443
perform TLS handshake using SNI
measure latency
return success/failure and latency
Success criteria:

TLS handshake completes
socket remains open
handshake time < timeout
Core Feature 2 — Working Combo Cache

Working combos must be stored in working_combos.json.

Example format:

{

“combos”: [

{

“ip”: “104.16.0.1”,

“sni”: “www.cloudflare.com”,

“avg_latency”: 45,

“success_rate”: 0.92,

“last_success”: “2026-04-20T10:22:00”

}

]

}

Rules:

load this file on startup
sort combos by:
highest success_rate
lowest latency
test cached combos first
update statistics after every successful connection
remove combos that repeatedly fail
Core Feature 3 — Automatic Combo Rotation

Implement a ComboManager class.

Responsibilities:

manage available combos
pick the best working combo
rotate if connection fails
trigger new scanning if all combos fail
Methods:

get_best_combo()

mark_success(ip, sni, latency)

mark_failure(ip, sni)

scan_new_combos()

If the current combo fails repeatedly, automatically switch to the next best one.

Core Feature 4 — TLS Connection Creation with SNI Spoofing

Implement a function:

async def create_tls_connection(ip, sni, port=443):

Steps:

create TCP socket to the IP
wrap socket with SSL context
set server_hostname = sni
disable certificate verification
enable TCP keepalive
Important socket options:

TCP_NODELAY

SO_KEEPALIVE

SSL config example:

context = ssl.create_default_context()

context.check_hostname = False

context.verify_mode = ssl.CERT_NONE

ssl_sock = context.wrap_socket(

sock,

server_hostname=sni

)

Core Feature 5 — Local Proxy Server

The program must run a local proxy server.

Example start command:

python sni_proxy.py --local-port 1080

Behavior:

Client (V2Ray / Xray / other tool)

↓

Local proxy (this program)

↓

TLS connection to Cloudflare IP using spoofed SNI

↓

Target upstream server

Proxy logic:

async def handle_client(reader, writer):

obtain connection from pool
forward client data to TLS socket
forward TLS responses back to client
handle disconnects gracefully
Use a buffer size of at least:

32768 bytes

Core Feature 6 — Connection Pool

Implement a connection pool to avoid constant reconnections.

Pool size example: 5–10 connections.

Responsibilities:

reuse healthy TLS tunnels
recreate dead connections
rebuild pool when combo rotates
Core Feature 7 — Health Monitoring

Run a background task:

Every 30 seconds:

verify current connection health
if latency spikes or connection drops → rotate combo
Every 5 minutes:

re-test known combos
optionally scan for new working combos
Core Feature 8 — Benchmark Mode

Add a CLI flag:

–benchmark

This mode should:

test all IP+SNI combinations
measure handshake latency
output ranked results
Example output:

Rank IP SNI Latency

1 104.16.0.1 www.cloudflare.com 41ms

2 172.67.1.10 cdnjs.cloudflare.com 55ms

3 162.159.36.1 workers.dev 63ms

Save results to:

benchmark_results.json

Core Feature 9 — Logging

Add structured logging with levels:

INFO

WARNING

ERROR

DEBUG

Example logs:

[INFO] Loaded 120 IPs

[INFO] Loaded 40 SNIs

[INFO] Generated 4800 combos

[INFO] Found working combo: 104.16.0.1 + www.cloudflare.com (45ms)

[WARNING] Current combo failed, rotating

[INFO] Switched to combo: 172.67.10.5 + cdnjs.cloudflare.com

Core Feature 10 — CLI Arguments

Support:

–local-port

–benchmark

–max-concurrency

–timeout

–buffer-size

–verbose

Example usage:

python sni_proxy.py --local-port 1080 --max-concurrency 50 --timeout 3 --verbose

Expected Result

The final program should:

automatically discover working IP+SNI combos
maintain a stable TLS tunnel
automatically rotate when blocked
cache good combos for faster startup
support benchmarking and monitoring
handle thousands of combinations efficiently with asyncio
Focus strongly on:

high concurrency
fast failure detection
automatic recovery
low latency data forwarding