# 🔍 RedSim Simple
### Basic Web Security Scanner

> Dokumentasi Produk untuk Client

---

## 1. Apa itu RedSim Simple?

RedSim Simple adalah tools scanning keamanan web yang dijalankan via command line. Cukup berikan satu domain atau IP address, tools ini akan otomatis memeriksa berbagai aspek keamanan website tersebut, lalu menghasilkan laporan lengkap dalam format HTML dan JSON.

Tools ini dirancang agar mudah digunakan, bahkan bagi yang baru belajar security.

---

## 2. Cara Pakai

**Install dependencies:**
```bash
pip install requests dnspython
```

**Jalankan scanner:**
```bash
python scanner.py -t namadomain.com
```

**Opsi tambahan:**

| Perintah | Fungsi |
|----------|--------|
| `python scanner.py -t domain.com` | Scan penuh (semua modul) |
| `--no-paths` | Skip pengecekan sensitive paths |
| `--json-only` | Hanya simpan laporan JSON |
| `-o /folder/output` | Tentukan folder penyimpanan laporan |

---

## 3. Yang Dicek

RedSim Simple melakukan 4 tahap pemeriksaan secara otomatis:

| Modul | Yang Diperiksa |
|-------|----------------|
| **DNS Info** | Resolve IP, reverse lookup, dan subdomain umum (www, mail, api, dev, dll.) |
| **Port Scan** | 19 port umum (FTP, SSH, MySQL, RDP, Redis, dll.) — port berbahaya ditandai otomatis |
| **HTTP Analysis** | Security headers, info server terekspose, kelemahan cookie, dan status HTTPS |
| **Sensitive Paths** | File/folder berbahaya yang terekspose: `/.env`, `/.git`, `/phpinfo.php`, `/backup.sql`, dll. |

---

## 4. Dependency — Tidak Perlu Tools Lain

RedSim Simple **tidak bergantung** pada tools eksternal seperti Nmap, Nikto, atau tools keamanan lainnya. Semua fungsi dibangun dari library Python murni:

- `socket` — port scan dan DNS lookup *(built-in Python, tidak perlu install)*
- `requests` — HTTP analysis dan cek sensitive paths
- `dnspython` — subdomain enumeration *(opsional, skip otomatis jika tidak ada)*
- `concurrent.futures` — threading di port scan *(built-in Python)*

Yang perlu di-install hanya:
```bash
pip install requests dnspython
```

Tidak ada binary eksternal, tidak ada dependency sistem — jalan di mana saja ada Python 3.

---

## 5. Output yang Diterima

Setelah scan selesai, dua file otomatis tersimpan di folder `output/`:

- `scan_<target>_<timestamp>.json` — Data mentah, cocok untuk diproses lebih lanjut
- `scan_<target>_<timestamp>.html` — Laporan visual yang bisa dibuka di browser

Laporan HTML menampilkan ringkasan temuan dengan warna berdasarkan tingkat risiko:

| Level | Warna | Keterangan |
|-------|-------|------------|
| Critical | 🔴 Merah | Temuan kritis, perlu segera ditangani |
| High | 🟠 Oranye | Risiko tinggi |
| Medium | 🟡 Kuning | Risiko sedang |
| Low | 🟢 Hijau | Risiko rendah |
| Info | 🔵 Biru | Informasi umum |

---

## 6. Untuk Siapa Tools Ini?

- **Pentester / red team** — rekon awal cepat sebelum assessment lebih dalam
- **Developer / sysadmin** — cek postur keamanan dasar website sendiri
- **Security analyst pemula** — kode flat, mudah dibaca dan dimodifikasi

---

## 7. ⚠️ Disclaimer

> Tools ini hanya boleh digunakan pada target yang **kamu miliki izin eksplisit** untuk ditest.
> Penggunaan tanpa izin adalah **ilegal** dan melanggar hukum yang berlaku.
