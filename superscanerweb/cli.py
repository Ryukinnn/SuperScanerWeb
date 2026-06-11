import argparse
import sys
from pathlib import Path

from . import __app_name__, __developer__, __version__
from .core import ScanConfig, ScanContext
from .modules import get_modules, run_modules
from .report import write_reports
from .utils import severity_rank


BANNER = rf"""
   _____                       _____                                  __          __  _
  / ____|                     / ____|                                 \ \        / / | |
 | (___  _   _ _ __   ___ _ _| (___   ___ __ _ _ __   ___ _ __ __      \ \  /\  / /__| |__
  \___ \| | | | '_ \ / _ \ '__\___ \ / __/ _` | '_ \ / _ \ '__/ _ \      \ \/  \/ / _ \ '_ \
  ____) | |_| | |_) |  __/ |  ____) | (_| (_| | | | |  __/ | |  __/       \  /\  /  __/ |_) |
 |_____/ \__,_| .__/ \___|_| |_____/ \___\__,_|_| |_|\___|_|  \___|        \/  \/ \___|_.__/
              | |
              |_|
 {__app_name__} v{__version__} | Developer: {__developer__}
 Defensive OSINT and website risk scanner
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="SuperScanerWeb",
        description="Scanner OSINT dan audit risiko website untuk Kali Linux.",
    )
    parser.add_argument("-t", "--target", help="Domain/URL target, contoh: https://example.com")
    parser.add_argument("--out", default="reports", help="Folder output report JSON/Markdown.")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout request per modul.")
    parser.add_argument("--rate-limit", type=float, default=0.25, help="Jeda antar request HTTP dalam detik.")
    parser.add_argument("--max-pages", type=int, default=25, help="Cadangan limit halaman untuk modul crawler ringan.")
    parser.add_argument("--max-js", type=int, default=12, help="Jumlah maksimum file JavaScript yang dianalisis.")
    parser.add_argument("--use-kali", action="store_true", help="Aktifkan integrasi tool Kali yang tersedia.")
    parser.add_argument("--active", action="store_true", help="Aktifkan modul aktif seperti nikto/nmap/sslscan. Wajib izin.")
    parser.add_argument("--yes-authorized", action="store_true", help="Konfirmasi bahwa kamu punya izin scan target.")
    parser.add_argument("--module", action="append", default=[], help="Jalankan modul tertentu by id. Bisa dipakai berkali-kali.")
    parser.add_argument("--list-modules", action="store_true", help="Tampilkan daftar modul dan keluar.")
    return parser


def print_modules() -> None:
    modules = get_modules()
    osint_count = sum(1 for module in modules if module.category.startswith("OSINT"))
    print(BANNER)
    print(f"Total modul: {len(modules)} | Modul OSINT: {osint_count}")
    print("")
    for module in modules:
        flags = []
        if module.requires_kali:
            flags.append("kali")
        if module.requires_active:
            flags.append("active")
        suffix = f" [{' / '.join(flags)}]" if flags else ""
        print(f"- {module.module_id:24} {module.category:16} {module.name}{suffix}")
        print(f"  {module.description}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_modules:
        print_modules()
        return 0
    if not args.target:
        parser.error("--target wajib diisi kecuali memakai --list-modules.")
    if not args.yes_authorized:
        print(BANNER)
        print("Scan dibatalkan: tambahkan --yes-authorized hanya jika target milikmu atau kamu punya izin tertulis.")
        return 2

    out_dir = Path(args.out)
    config = ScanConfig(
        target=args.target,
        out_dir=out_dir,
        timeout=max(3, args.timeout),
        rate_limit=max(0.0, args.rate_limit),
        max_pages=max(1, args.max_pages),
        max_js=max(0, args.max_js),
        active=args.active,
        use_kali=args.use_kali,
        selected_modules=args.module,
    )
    print(BANNER)
    print(f"[+] Target       : {args.target}")
    print(f"[+] Kali tools   : {'on' if args.use_kali else 'off'}")
    print(f"[+] Active checks: {'on' if args.active else 'off'}")
    print("")

    try:
        ctx = ScanContext(config)
        results = run_modules(ctx)
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh user.")
        return 130
    except Exception as exc:
        print(f"[!] Gagal menjalankan scan: {exc}")
        return 1

    print("[+] Ringkasan:")
    for item in sorted(results, key=lambda r: severity_rank(r.severity), reverse=True):
        marker = "skip" if item.skipped else item.severity
        print(f"    [{marker:8}] {item.module_id:24} {item.summary}")
    print("")
    print("[+] Official email kandidat:")
    if ctx.official_emails:
        for email in ctx.official_emails:
            print(f"    - {email}")
    else:
        print("    Belum ditemukan. Cek report untuk detail sumber.")

    json_path, md_path = write_reports(ctx, results)
    print("")
    print(f"[+] JSON report : {json_path}")
    print(f"[+] MD report   : {md_path}")
    print("[+] Selesai.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
