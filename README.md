# SuperScanerWeb

**SuperScanerWeb** adalah tool scanner OSINT dan audit risiko website untuk Kali Linux.

- Nama tool: **SuperScanerWeb**
- Developer: **Ryukinnn**
- Fokus: risiko website, link/endpoint terekspos, konfigurasi publik, dan OSINT pendukung
- Output: report **JSON** dan **Markdown**

> Gunakan hanya pada website/aset yang kamu miliki atau sudah mendapat izin tertulis. Tool ini dibuat untuk defensive security, bug bounty berizin, audit internal, dan hardening.

## Fitur Utama

- Mencari indikator risiko website tanpa exploit, brute force, atau bypass.
- Mencari link, endpoint, path, file, sitemap, robots, JavaScript endpoint, dan URL arsip yang tidak seharusnya terekspos publik.
- Setiap hasil modul menyertakan kandidat **email resmi** dari website yang discan.
- Memiliki lebih dari 20 modul OSINT/risk audit.
- Bisa memakai tool bawaan Kali Linux jika tersedia: `whois`, `whatweb`, `wafw00f`, `nikto`, `nmap`, dan `sslscan`.
- Modul aktif seperti `nikto`, `nmap`, dan `sslscan` hanya berjalan jika kamu menambahkan `--active`.

## Instalasi di Kali Linux

```bash
git clone https://github.com/Ryukinnn/SuperScanerWeb.git
cd SuperScanerWeb
bash setup.sh
```

Opsional untuk memaksimalkan integrasi Kali:

```bash
sudo apt update
sudo apt install -y whois dnsutils whatweb wafw00f nikto nmap sslscan
```

## Cara Pakai

Scan default:

```bash
source .venv/bin/activate
python3 superscanerweb.py --target https://example.com --yes-authorized
```

Scan dengan tool Kali non-agresif:

```bash
python3 superscanerweb.py --target https://example.com --yes-authorized --use-kali
```

Scan dengan modul aktif. Gunakan hanya untuk aset berizin:

```bash
python3 superscanerweb.py --target https://example.com --yes-authorized --use-kali --active
```

Lihat daftar modul:

```bash
python3 superscanerweb.py --list-modules
```

Jalankan modul tertentu:

```bash
python3 superscanerweb.py --target https://example.com --yes-authorized --module security_txt --module exposed_links
```

## Daftar Modul

Modul OSINT dan risk audit bawaan:

1. `official_email` - mencari email resmi dari halaman, security.txt, kontak, dan whois.
2. `security_txt` - memeriksa kontak keamanan RFC 9116.
3. `dns_records` - inventaris A/AAAA/NS/SOA/TXT.
4. `mx_records` - memeriksa mail server MX.
5. `spf_dmarc` - memeriksa SPF dan DMARC.
6. `dns_caa` - memeriksa CAA record.
7. `tls_certificate` - membaca metadata sertifikat TLS.
8. `http_headers` - audit header keamanan HTTP.
9. `cookie_flags` - audit Secure, HttpOnly, dan SameSite.
10. `cors_policy` - review CORS wildcard/credentials.
11. `content_security_policy` - review CSP dan directive berisiko.
12. `robots_txt` - mencari path sensitif di robots.txt.
13. `sitemap_links` - mencari URL sensitif di sitemap.
14. `html_link_inventory` - inventaris link pada halaman awal.
15. `exposed_links` - mencari link publik yang tampak sensitif.
16. `javascript_endpoints` - ekstraksi endpoint dari JavaScript publik.
17. `secret_patterns` - mencari pola token/secret di HTML dan JavaScript publik.
18. `sensitive_paths` - probe ringan path sensitif umum seperti `.env`, backup, debug, dan API docs.
19. `directory_listing` - mendeteksi directory listing terbuka.
20. `technology_fingerprint` - fingerprint teknologi dari header dan HTML.
21. `cms_admin_surface` - mendeteksi permukaan admin CMS umum.
22. `url_parameters` - memetakan parameter URL yang perlu review manual.
23. `ct_subdomains` - enumerasi subdomain dari Certificate Transparency.
24. `wayback_urls` - review URL publik dari Wayback Machine.
25. `takeover_cname` - mencari hint risiko subdomain takeover dari CNAME.

Integrasi Kali:

26. `kali_whois` - OSINT whois.
27. `kali_whatweb` - fingerprint dengan WhatWeb.
28. `kali_wafw00f` - deteksi WAF.
29. `kali_nikto` - audit web server aktif dengan Nikto, perlu `--active`.
30. `kali_nmap_http` - surface check HTTP dengan Nmap, perlu `--active`.
31. `kali_sslscan` - audit TLS dengan SSLScan, perlu `--active`.

## Output Report

Report tersimpan di folder `reports/`:

- `domain-timestamp.json`
- `domain-timestamp.md`

Saat scan selesai, terminal dan report akan menampilkan informasi detail:

- Ringkasan keamanan: highest severity, jumlah modul berjalan, modul dengan temuan, modul actionable, dan jumlah URL/path berisiko.
- Kandidat email resmi dari website yang sedang discan.
- Daftar URL/path berisiko prioritas lengkap dengan severity, status HTTP jika ada, modul sumber, dan alasan risiko.
- Katalog **20 modul utama** bernomor `1` sampai `20`, masing-masing dengan fungsi, kegunaan, dan output keamanan yang berbeda.
- Ringkasan hasil semua modul, jumlah finding, jumlah URL berisiko per modul, dan detail evidence.

Setiap modul menyimpan:

- `module_id`
- `module_name`
- `category`
- `severity`
- `summary`
- `findings`
- `evidence`
- `recommendations`
- `official_emails`

Field tambahan pada JSON report:

- `security_summary`
- `module_catalog_20`
- `risky_urls`

## Catatan Etika dan Scope

SuperScanerWeb tidak dibuat untuk mengambil alih sistem, mengeksploitasi celah, melakukan brute force, bypass login, atau tindakan destruktif. Scanner ini membantu menemukan indikator risiko yang perlu diverifikasi manual oleh pemilik aset.

Selalu simpan izin scan, scope domain, dan waktu pengujian sebelum menjalankan modul aktif.
