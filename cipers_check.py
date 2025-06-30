#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IronSSLProbe - SSL/TLS Certificate and Cipher Suite Checker
Author: Sebux
Description:
    This script connects to a given hostname and port to retrieve and display SSL/TLS certificate details,
    checks the certificate validity, and enumerates supported cipher suites,
    highlighting weak ciphers for security awareness.

Usage:
    python ironsslprobe.py

Requirements:
    - Python 3.7+
"""
import socket
import ssl
from datetime import datetime
import warnings

CIPHERS_TO_TEST = {
    'ECDHE-RSA-AES256-GCM-SHA384': 'strong',
    'ECDHE-ECDSA-AES256-GCM-SHA384': 'strong',
    'ECDHE-RSA-AES128-GCM-SHA256': 'strong',
    'ECDHE-ECDSA-AES128-GCM-SHA256': 'strong',
    'AES256-GCM-SHA384': 'strong',
    'AES128-GCM-SHA256': 'strong',
    'ECDHE-RSA-CHACHA20-POLY1305': 'strong',
    'ECDHE-ECDSA-CHACHA20-POLY1305': 'strong',
    'DHE-RSA-AES256-GCM-SHA384': 'strong',
    'DHE-RSA-AES128-GCM-SHA256': 'strong',

    'AES256-SHA': 'weak',
    'AES128-SHA': 'weak',
    'DES-CBC3-SHA': 'weak',
    'ECDHE-RSA-DES-CBC3-SHA': 'weak',
    'ECDHE-ECDSA-DES-CBC3-SHA': 'weak',
    'RC4-SHA': 'weak',
    'EXP-RC4-MD5': 'weak',
    'LOW': 'weak',
    'aNULL': 'weak',
    'eNULL': 'weak',
    'NULL': 'weak',
    'MD5': 'weak',
}

def get_cert_info(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()

            subject = cert.get('subject', ())
            issuer = cert.get('issuer', ())
            print("Certificate Information:")
            print(f"  Subject:")
            for item in subject:
                print(f"    {item[0][0]}: {item[0][1]}")
            print(f"  Issuer:")
            for item in issuer:
                print(f"    {item[0][0]}: {item[0][1]}")

            print(f"  Valid from: {cert.get('notBefore')}")
            print(f"  Valid until: {cert.get('notAfter')}")

            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.utcnow()

            if now < not_before:
                print("  ⚠️ Certificate is NOT yet valid!")
            elif now > not_after:
                print("  ⚠️ Certificate is EXPIRED!")
            else:
                print("  ✅ Certificate is currently valid.")

            cipher = ssock.cipher()
            print(f"\nCurrent SSL Connection Cipher: {cipher[0]} (Protocol: {cipher[1]}, Bits: {cipher[2]})")

def test_ciphers(hostname, port=443):
    print("\nTesting supported TLS 1.2 and earlier cipher suites:\n")

    supported_ciphers = []

    for cipher, strength in CIPHERS_TO_TEST.items():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.options |= ssl.OP_NO_TLSv1_3
            context.options |= ssl.OP_NO_TLSv1_1
            context.options |= ssl.OP_NO_TLSv1

        try:
            context.set_ciphers(cipher)
        except ssl.SSLError:
            continue

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    negotiated_cipher = ssock.cipher()
                    supported_ciphers.append((negotiated_cipher[0], strength))
        except Exception:
            continue

    if not supported_ciphers:
        print("  No TLS 1.2 or earlier ciphers supported or server uses TLS 1.3 only.\n")
        return

    for cipher_name, strength in supported_ciphers:
        if strength == 'weak':
            print(f"  ⚠️ WEAK cipher supported: {cipher_name}")
        else:
            print(f"  ✅ Strong cipher supported: {cipher_name}")

if __name__ == "__main__":
    host = input("Enter hostname to check: ").strip()
    port_input = input("Enter port (default 443): ").strip()
    port = int(port_input) if port_input else 443

    print(f"\nFetching certificate info for {host}:{port}\n")
    get_cert_info(host, port)

    test_ciphers(host, port)
