import struct
import os
import random


class ClientHelloMaker:
    # Enhanced TLS 1.3 Client Hello with better randomization
    # Using TLS 1.3 with modern cipher suites
    tls_ch_template_str = "1603010200010001fc0303"  # TLS header + handshake header
    
    # Default cipher suites (TLS 1.3)
    CIPHER_SUITES = bytes.fromhex(
        "1301"  # TLS_AES_256_GCM_SHA384
        "1302"  # TLS_AES_128_GCM_SHA256
        "1303"  # TLS_CHACHA20_POLY1305_SHA256
        "c02b"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        "c02f"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        "cca9"  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        "c02c"  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        "c02b"  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    )
    
    # Supported versions
    SUPPORTED_VERSIONS = bytes.fromhex("0304")  # TLS 1.3
    
    # Supported groups
    SUPPORTED_GROUPS = bytes.fromhex(
        "001d"  # secp256r1
        "001e"  # secp384r1
        "001f"  # secp521r1
        "0020"  # x25519
        "0021"  # x448
    )
    
    # Signature algorithms
    SIGNATURE_ALGORITHMS = bytes.fromhex(
        "0403"  # ecdsa_secp256r1_sha256
        "0503"  # ecdsa_secp384r1_sha384
        "0804"  # rsa_pss_rsae_sha256
        "0805"  # rsa_pss_rsae_sha384
        "0806"  # rsa_pss_rsae_sha512
        "0201"  # rsa_pkcs1_sha256
        "0202"  # rsa_pkcs1_sha384
        "0203"  # rsa_pkcs1_sha512
    )
    
    # Extension types
    EXT_SERVER_NAME = 0x0000
    EXT_SUPPORTED_VERSIONS = 0x002b
    EXT_KEY_SHARE = 0x0029
    EXT_SIGNATURE_ALGORITHMS = 0x000d
    EXT_SUPPORTED_GROUPS = 0x000a
    EXT_ALPN = 0x0010
    EXT_PADDING = 0x0015
    
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes,
                              key_share: bytes) -> bytes:
        """Generate a more realistic TLS 1.3 Client Hello with proper extensions"""
        
        # Randomize session ID
        if len(sess_id) != 32:
            sess_id = os.urandom(32)
        
        # Build extensions
        extensions = b""
        
        # 1. Server Name Indication (SNI)
        sni_ext = struct.pack("!H", cls.EXT_SERVER_NAME)  # Extension type
        sni_len = len(target_sni) + 5  # Length of extension data
        sni_ext += struct.pack("!H", sni_len)
        sni_ext += struct.pack("!H", len(target_sni) + 3)  # Server name list length
        sni_ext += b"\x00"  # Name type (host_name)
        sni_ext += struct.pack("!H", len(target_sni))
        sni_ext += target_sni
        extensions += sni_ext
        
        # 2. Supported Versions (TLS 1.3)
        vers_ext = struct.pack("!H", cls.EXT_SUPPORTED_VERSIONS)
        vers_ext += struct.pack("!H", 3)  # Length
        vers_ext += b"\x03"  # Client version
        vers_ext += cls.SUPPORTED_VERSIONS
        extensions += vers_ext
        
        # 3. Key Share
        key_share_ext = struct.pack("!H", cls.EXT_KEY_SHARE)
        key_share_ext += struct.pack("!H", len(key_share) + 2)
        key_share_ext += struct.pack("!H", len(key_share))
        key_share_ext += key_share
        extensions += key_share_ext
        
        # 4. Signature Algorithms
        sig_ext = struct.pack("!H", cls.EXT_SIGNATURE_ALGORITHMS)
        sig_ext += struct.pack("!H", len(cls.SIGNATURE_ALGORITHMS))
        sig_ext += cls.SIGNATURE_ALGORITHMS
        extensions += sig_ext
        
        # 5. Supported Groups
        groups_ext = struct.pack("!H", cls.EXT_SUPPORTED_GROUPS)
        groups_ext += struct.pack("!H", len(cls.SUPPORTED_GROUPS) + 2)
        groups_ext += struct.pack("!H", len(cls.SUPPORTED_GROUPS))
        groups_ext += cls.SUPPORTED_GROUPS
        extensions += groups_ext
        
        # 6. ALPN (Application Layer Protocol Negotiation)
        alpn_ext = struct.pack("!H", cls.EXT_ALPN)
        alpn_protocols = b"\x08http/1.1"  # http/1.1
        alpn_ext += struct.pack("!H", len(alpn_protocols) + 2)
        alpn_ext += struct.pack("!H", len(alpn_protocols))
        alpn_ext += alpn_protocols
        extensions += alpn_ext
        
        # 7. Padding extension (to make it look more natural)
        padding_len = random.randint(50, 200)
        padding_ext = struct.pack("!H", cls.EXT_PADDING)
        padding_ext += struct.pack("!H", padding_len)
        padding_ext += os.urandom(padding_len)
        extensions += padding_ext
        
        # Build the Client Hello
        # Handshake type (1 = Client Hello)
        handshake_type = b"\x01"
        
        # Version (TLS 1.2 for compatibility)
        version = b"\x03\x03"
        
        # Random (32 bytes)
        if len(rnd) != 32:
            rnd = os.urandom(32)
        
        # Session ID
        session_id = sess_id
        
        # Cipher suites
        cipher_suites = cls.CIPHER_SUITES
        
        # Compression (1 byte: null)
        compression = b"\x00"
        
        # Extensions length
        extensions_len = struct.pack("!H", len(extensions))
        
        # Combine all parts
        client_hello = (
            handshake_type +
            version +
            rnd +
            session_id +
            struct.pack("!H", len(cipher_suites)) +
            cipher_suites +
            compression +
            extensions_len +
            extensions
        )
        
        # Add TLS record header
        record = b"\x16" + version + struct.pack("!H", len(client_hello)) + client_hello
        
        return record

    @classmethod
    def parse_client_hello(cls, client_hello_bytes: bytes):
        """Parse Client Hello to extract SNI and key share"""
        if len(client_hello_bytes) < 5:
            raise ValueError("Invalid Client Hello: too short")
        
        # Skip TLS record header (5 bytes)
        # Skip handshake type (1) + version (2) + length (2)
        handshake_start = 5
        
        if len(client_hello_bytes) < handshake_start + 34:
            raise ValueError("Invalid Client Hello: not enough data")
        
        # Random (32 bytes at offset 0 in handshake)
        rnd = client_hello_bytes[handshake_start:handshake_start + 32]
        
        # Session ID (next 32 bytes)
        sess_id_start = handshake_start + 32
        sess_id_len = client_hello_bytes[sess_id_start]
        sess_id = client_hello_bytes[sess_id_start + 1:sess_id_start + 1 + sess_id_len]
        
        # Find SNI extension
        # We need to parse extensions to find SNI
        # This is a simplified parser
        try:
            # Try to find SNI in the raw bytes
            sni_start = client_hello_bytes.find(b"\x00\x00")  # Extension type 0 = SNI
            if sni_start > 0 and sni_start < len(client_hello_bytes) - 10:
                # Skip extension type (2) and length (2)
                sni_list_start = sni_start + 4
                if sni_list_start + 3 < len(client_hello_bytes):
                    # Skip name type (1) and name length (2)
                    name_len = struct.unpack("!H", client_hello_bytes[sni_list_start + 1:sni_list_start + 3])[0]
                    tls_sni = client_hello_bytes[sni_list_start + 3:sni_list_start + 3 + name_len].decode()
                else:
                    tls_sni = b""
            else:
                tls_sni = b""
        except:
            tls_sni = b""
        
        # Key share - simplified
        key_share = os.urandom(32)
        
        return rnd, sess_id, tls_sni, key_share

    @classmethod
    def get_client_response_with(cls, app_data1: bytes):
        """Generate TLS Change Cipher Spec + Application Data"""
        return cls.tls_change_cipher + cls.tls_app_data_header + struct.pack("!H", len(app_data1)) + app_data1

    @classmethod
    def parse_client_response(cls, client_response_bytes: bytes):
        """Parse client response"""
        if len(client_response_bytes) < 11:
            raise ValueError("Invalid client response: too short")
        app_data1 = client_response_bytes[11:]
        return app_data1
    
    @classmethod
    def generate_random_sni(cls) -> bytes:
        """Generate a random realistic SNI from common domains"""
        common_snis = [
            b"auth.vercel.com",
            b"www.google.com",
            b"www.cloudflare.com",
            b"www.microsoft.com",
            b"www.amazon.com",
            b"www.apple.com",
            b"www.facebook.com",
            b"www.twitter.com",
            b"www.instagram.com",
            b"www.youtube.com",
            b"www.reddit.com",
            b"www.linkedin.com",
            b"www.github.com",
            b"www.stackoverflow.com",
            b"cdn.jsdelivr.net",
            b"unpkg.com",
            b"fonts.googleapis.com",
            b"ajax.googleapis.com",
        ]
        return random.choice(common_snis)


class ServerHelloMaker:
    tls_sh_template_str = "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e"
    tls_sh_template = bytes.fromhex(tls_sh_template_str)
    static1 = tls_sh_template[:11]
    static2 = b"\x20"
    static3 = tls_sh_template[76:95]
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_server_hello_with(cls, rnd: bytes, sess_id: bytes, key_share: bytes, app_data1: bytes):
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + key_share + cls.tls_change_cipher + cls.tls_app_data_header + struct.pack(
            "!H", len(app_data1)) + app_data1

    @classmethod
    def parse_server_hello(cls, server_hello_bytes: bytes):
        assert len(server_hello_bytes) >= 159
        rnd = server_hello_bytes[11:43]
        sess_id = server_hello_bytes[44:76]
        key_share = server_hello_bytes[95:127]
        app_data1 = server_hello_bytes[138:]
        assert cls.get_server_hello_with(rnd, sess_id, key_share, app_data1) == server_hello_bytes
        return rnd, sess_id, key_share, app_data1
