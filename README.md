# 🛡️ BugSentinel

**BugSentinel** adalah alat pemindai kerentanan web berbasis Python, yang dapat mendeteksi berbagai jenis kerentanan umum dan berbahaya seperti:

- ✅ XSS (Cross-Site Scripting)
- ✅ SQL Injection (SQLi)
- ✅ RCE (Remote Code Execution)
- ✅ LFI (Local File Inclusion)
- ✅ SSRF (Server-Side Request Forgery)
- ✅ Directory Listing
- ✅ Sensitive File Exposure
- ✅ Authentication Bypass
- ✅ Header Security Issues
- ✅ CMS & Server Fingerprinting

---

## 🚀 Cara Penggunaan

### 1. Pemindaian Tunggal (otomatis menambahkan parameter jika kosong)

```bash
python3 bugsentinel.py -u "https://target.com/"
