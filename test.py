import socket
import ssl
import time

# چند کمبوی متنوع از لیست
test_combos = [
    ("npmjs.com", "104.17.135.117"),
    ("npmjs.com", "104.17.134.117"),
    ("sourceforge.net", "104.18.12.149"),
    ("sourceforge.net", "104.18.13.149"),
    ("registry.npmjs.org", "104.16.4.34"),
    ("registry.npmjs.org", "104.16.0.34"),
    ("registry.npmjs.org", "104.16.8.34"),
    ("hcaptcha.com", "104.19.230.21"),
    ("hcaptcha.com", "104.19.229.21"),
    ("dashboard.hcaptcha.com", "104.19.230.21"),
    ("api.hcaptcha.com", "104.19.229.21"),
    ("e7.c.lencr.org", "104.18.21.213"),
]

def test_combo(sni, ip, port=443, timeout=8):
    tcp_ok = False
    tls_ok = False
    tcp_time = None
    tls_time = None
    error = None

    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        t0 = time.time()
        sock.connect((ip, port))
        tcp_time = time.time() - t0
        tcp_ok = True

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        t1 = time.time()
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        tls_time = time.time() - t1
        tls_ok = True

        ssock.close()

    except socket.timeout:
        error = "TIMEOUT"
    except OSError as e:
        error = str(e)
    except ssl.SSLError as e:
        error = f"SSL {e}"
    except Exception as e:
        error = str(e)

    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

    return tcp_ok, tls_ok, tcp_time, tls_time, error


print("Testing SNI + IP combos\n")

working = []
tcp_only = []
failed = []

for i,(sni,ip) in enumerate(test_combos,1):

    tcp_ok,tls_ok,tcp_t,tls_t,err = test_combo(sni,ip)

    if tls_ok:
        total = tcp_t + tls_t
        print(f"{i:02d} OK   {sni:25} {ip:15}  {total:.2f}s")
        working.append((sni,ip,total))

    elif tcp_ok:
        print(f"{i:02d} TCP  {sni:25} {ip:15}  TLS_FAIL {err}")
        tcp_only.append((sni,ip))

    else:
        print(f"{i:02d} FAIL {sni:25} {ip:15}  {err}")
        failed.append((sni,ip))


print("\nSummary")
print("Full success:",len(working))
print("TCP only:",len(tcp_only))
print("Failed:",len(failed))

if working:
    working.sort(key=lambda x:x[2])
    print("\nFastest working combos:")
    for sni,ip,t in working[:5]:
        print(f"{sni} -> {ip}  {t:.2f}s")
