#!/usr/bin/env python3
import ssl
import socket
import hashlib
import sys
import tempfile
import subprocess
import os

HOST = 'tls-lab.local'            # used for SNI and logs
HOST_IP = '10.10.0.10'            # actual IP to connect to (Docker server IP)
PORT = 9443

# <- PUT the expected SHA256 hex (pubkey) here (from openssl command above)
EXPECTED_HEX = '0426e2509f69f550d1640cc074ee1d3b71da0123e96e4568e3b56d6c42878608'


def fetch_cert_der_unverified(host: str, port: int, connect_ip: str = None) -> bytes:
    """Connect with an unverified context and return DER-encoded server cert.
       If connect_ip is provided, the TCP connection is made to that IP while
       the TLS SNI uses `host` (correct for container setups)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    target = (connect_ip, port) if connect_ip else (host, port)
    with socket.create_connection(target, timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    return der


def pubkey_hash_from_der_using_openssl(der_bytes: bytes) -> str:
    """
    Preferred: write DER to a temp file, call openssl to extract pubkey DER and sha256sum it.
    Returns lowercase hex string (no spaces).
    Requires openssl to be available on PATH.
    """
    with tempfile.NamedTemporaryFile(delete=False) as f:
        fname = f.name
        f.write(der_bytes)
    try:
        cmd = (
            f"openssl x509 -in {fname} -inform DER -pubkey -noout | "
            "openssl pkey -pubin -outform der | sha256sum"
        )
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
        hexstr = out.split()[0].lower()
        return hexstr
    finally:
        try:
            os.remove(fname)
        except Exception:
            pass


def fallback_pubkey_hash_from_der(der_bytes: bytes) -> str:
    return hashlib.sha256(der_bytes).hexdigest()


def make_unverified_context():
    """Return an SSL context that does NOT verify the server cert (for lab demo)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_page_via_tls_socket(connect_ip: str, host: str, port: int, context: ssl.SSLContext, path: str = "/") -> bytes:
    """
    Minimal HTTPS GET implemented over a TLS-wrapped socket:
    - Connects TCP to connect_ip:port (avoids DNS)
    - Wraps socket with TLS using server_hostname=host (SNI preserved)
    - Writes a simple HTTP/1.1 GET and returns the response bytes (headers+body)
    """
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: pinned-client/1.0\r\n\r\n"
    with socket.create_connection((connect_ip, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ss:
            ss.sendall(request.encode("ascii"))
            # read until EOF
            chunks = []
            while True:
                data = ss.recv(4096)
                if not data:
                    break
                chunks.append(data)
    return b"".join(chunks)


def main():
    if EXPECTED_HEX == 'REPLACE_WITH_EXPECTED_HEX' or not EXPECTED_HEX:
        print("ERROR: You must set EXPECTED_HEX in the script (the expected pubkey SHA256 hex).")
        sys.exit(2)

    print(f"Connecting to {HOST}:{PORT} (TCP -> {HOST_IP}) and fetching certificate (unverified)...")
    try:
        der = fetch_cert_der_unverified(HOST, PORT, connect_ip=HOST_IP)
    except Exception as e:
        print("ERROR: failed to fetch certificate:", e)
        sys.exit(2)

    observed = None
    try:
        observed = pubkey_hash_from_der_using_openssl(der)
        print("Observed server pubkey SHA256 (via openssl):", observed)
    except Exception:
        observed = fallback_pubkey_hash_from_der(der)
        print("OpenSSL not available or failed — using fallback (sha256 of full cert):", observed)
        print("Note: fallback hashes the full cert; use openssl method to compute expected pubkey hash for best compatibility.")

    if observed != EXPECTED_HEX.lower():
        print("\n*** PIN MISMATCH: observed != expected ***")
        print("Observed :", observed)
        print("Expected :", EXPECTED_HEX.lower())
        print("Aborting — possible MITM detected.")
        sys.exit(2)

    print("\nPin matched — proceeding to fetch page (using unverified TLS socket for demo)...")
    try:
        ctx = make_unverified_context()
        resp_bytes = fetch_page_via_tls_socket(HOST_IP, HOST, PORT, ctx, path="/")
        # split headers/body for nicer output
        headers_end = resp_bytes.find(b"\r\n\r\n")
        if headers_end != -1:
            headers = resp_bytes[:headers_end].decode("utf-8", errors="replace")
            body = resp_bytes[headers_end + 4:]
            print("Response headers:\n", headers)
            print("\nBody (first 1024 bytes):\n")
            print(body[:1024].decode("utf-8", errors="replace"))
        else:
            print("Full response (first 2048 bytes):")
            print(resp_bytes[:2048].decode("utf-8", errors="replace"))
    except Exception as e:
        print("Failed to fetch page after pin match. Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
