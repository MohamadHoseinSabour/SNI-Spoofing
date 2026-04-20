import socket
import ssl

def test_tls(ip, port, sni, host):
    try:
        sock = socket.create_connection((ip, port), timeout=10)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssock = context.wrap_socket(sock, server_hostname=sni)
        print(f"✅ TLS OK with SNI={sni}")
        
        # ارسال درخواست HTTP با Host واقعی
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        ssock.send(request.encode())
        response = ssock.recv(4096).decode('utf-8', errors='ignore')
        print(f"Response: {response[:200]}")
        
        ssock.close()
    except Exception as e:
        print(f"❌ Failed: {e}")

# تست با مقادیر کانفیگت
test_tls('104.17.135.117', 443, 'npmjs.com', 'exonerate.pages.dev')
