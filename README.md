# RedSim Simple 🔍

Scanner keamanan web sederhana untuk keperluan rekon dasar.

## Install

```bash
pip install -r requirements.txt
```

## Cara Pakai

```bash
# Scan penuh
python scanner.py -t example.com

# Skip cek sensitive paths
python scanner.py -t example.com --no-paths

# Hanya simpan JSON (tidak buat HTML)
python scanner.py -t example.com --json-only

# Tentukan folder output
python scanner.py -t example.com -o /tmp/hasil
```

## Yang Dicek

| Modul           | Fungsi                                            |
|-----------------|---------------------------------------------------|
| DNS Info        | Resolve IP, reverse lookup, subdomain sederhana   |
| Port Scan       | Cek 19 port umum (TCP)                            |
| HTTP Analysis   | Security headers, server info, cookies, HTTPS     |
| Sensitive Paths | Cek file/folder sensitif yang terekspose           |

## Output

Laporan tersimpan di folder `output/` dalam format:
- `scan_<target>_<timestamp>.json`
- `scan_<target>_<timestamp>.html`

---
*Gunakan hanya pada target yang kamu punya izin untuk ditest.*
