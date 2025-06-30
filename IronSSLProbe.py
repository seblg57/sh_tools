#!/usr/bin/env python3
"""
Netcheck Simple SSL Tester
Author: Sebux the Boss
Date: 2025-06-30

This script performs basic network checks on a given hostname:
- DNS resolution
- SSL/TLS handshake verification
- HTTPS GET request test

Usage:
    Run the script and input the hostname and optional port.
"""
import socket
import ssl
import urllib.request

def test_ssl(hostname, port=443, timeout=5):
    # Test DNS resolution
    try:
        ip = socket.gethostbyname(hostname)
        print(f'DNS resolution OK: {hostname} -> {ip}')
    except Exception as e:
        print(f'DNS resolution failed: {e}')
        return False

    # Test SSL handshake
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(timeout)
            s.connect((hostname, port))
            cert = s.getpeercert()
            cipher = s.cipher()
            print(f'SSL handshake OK: cipher={cipher[0]}')
            common_name = dict(x[0] for x in cert.get('subject', []))['commonName']
            print(f'Certificate common name: {common_name}')
    except Exception as e:
        print(f'SSL handshake failed: {e}')
        return False

    # Test HTTPS request
    try:
        ctx = ssl.create_default_context()
        url = f'https://{hostname}'
        with urllib.request.urlopen(url, context=ctx, timeout=timeout) as response:
            if response.status == 200:
                print(f'HTTPS request OK: {url} returned status {response.status}')
                return True
            else:
                print(f'HTTPS request returned status {response.status}')
                return False
    except Exception as e:
        print(f'HTTPS request failed: {e}')
        return False

if __name__ == '__main__':
    host = input('Hostname to test: ').strip()
    port_str = input('Port (default 443): ').strip()
    port = int(port_str) if port_str else 443

    print(f'Testing {host}:{port}...\n')
    result = test_ssl(host, port)
    if result:
        print('\nAll checks passed successfully!')
    else:
        print('\nSome checks failed.')
