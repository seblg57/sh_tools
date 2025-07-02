#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IronXSSProbe - Basic Reflected XSS Vulnerability Scanner
Author: Sebux
Description:
    Simple Python script to test for reflected Cross-Site Scripting (XSS)
    vulnerabilities by injecting a test payload into a specified URL parameter.
    Not a full scanner, for quick checks only.

Pour test

Usage:
    python ironxssprobe.py

Requirements:
    - Python 3.7+
    - requests
    - beautifulsoup4
"""
import requests
from bs4 import BeautifulSoup

def test_xss(url, param='q'):
    payload = '<script>alert("XSS")</script>'
    if '?' in url:
        test_url = f"{url}&{param}={payload}"
    else:
        test_url = f"{url}?{param}={payload}"

    try:
        resp = requests.get(test_url, timeout=10)
        content = resp.text
        if payload in content:
            print(f"⚠️ Possible XSS vulnerability detected at {test_url}")
        else:
            print(f"✅ No reflected XSS detected at {url} with param '{param}'.")
    except Exception as e:
        print(f"❌ Error testing {url}: {e}")

if __name__ == "__main__":
    target = input("Enter the target URL: ").strip()
    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'http://' + target  # add default http scheme

    parameter = input("Enter the parameter to test (default 'q'): ").strip() or 'q'
    test_xss(target, parameter)
