"""
main.py — Phishing URL Detector
Commit 3: threat feed integration and cli

Kullanım:
  python main.py https://paypa1-secure.tk/login
  python main.py url1 url2 url3
  python main.py --file urls.txt
  python main.py --demo
  python main.py url --json
  python main.py url --vt-key YOUR_KEY   # VirusTotal entegrasyonu
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

from url_features import URLFeatureExtractor
from heuristics   import PhishingHeuristicsEngine


# ─────────────────────────────────────────────────────────────────────────────
# ANSI Renk Kodları
# ─────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"; BOLD  = "\033[1m"
GREEN  = "\033[92m"; YELLOW= "\033[93m"; ORANGE= "\033[33m"
RED    = "\033[91m"; DKRED = "\033[31m"; CYAN  = "\033[96m"
GRAY   = "\033[90m"; WHITE = "\033[97m"

BANNER = f"""{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════╗
║       🎣 PHISHING URL DETECTOR  v1.0                        ║
╠══════════════════════════════════════════════════════════════╣
║  Heuristics · Entropi · Typosquatting · VirusTotal          ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""

# Demo URL'leri
DEMO_URLS = [
    "https://paypa1-secure-login.tk/account/verify",
    "https://192.168.1.1/banking/login.php",
    "https://google.com",
    "https://microsoft-support-helpdesk.xyz/update/credential",
    "http://apple.com.evil-phishing.ml/signin",
    "https://github.com",
    "https://bit.ly/3xKpQ2r",
    "https://amazon.com-secure-payment.ru/cart/signin",
]


# ─────────────────────────────────────────────────────────────────────────────
# VirusTotal Entegrasyonu
# ─────────────────────────────────────────────────────────────────────────────

def check_virustotal(url: str, api_key: str) -> dict:
    """VirusTotal URL taraması (opsiyonel)."""
    import base64

    try:
        # URL'yi base64 ile encode et (VT v3 API gereksinimi)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        req = urllib.request.Request(endpoint)
        req.add_header("x-apikey", api_key)

        with urllib.request.urlopen(req, timeout=10) as resp:
            data  = json.loads(resp.read())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious",  0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless",   0),
                "total":      sum(stats.values()),
                "error":      "",
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # URL daha önce taranmamış — gönder
            return {"error": "URL daha önce taranmamış (VT'de yok)"}
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Terminal Raporu
# ─────────────────────────────────────────────────────────────────────────────

def print_report(features, score, vt_result: dict = None) -> None:
    LEVEL_COLORS = {
        "SAFE":     GREEN,
        "LOW":      YELLOW,
        "MEDIUM":   ORANGE,
        "HIGH":     RED,
        "CRITICAL": DKRED,
    }
    color = LEVEL_COLORS.get(score.risk_level, GRAY)

    # URL kısalt göster
    url_short = score.url[:65] + "..." if len(score.url) > 65 else score.url

    print(f"\n{BOLD}{CYAN}{'╔' + '═' * 60 + '╗'}{RESET}")
    print(f"{BOLD}{CYAN}║  🎣 {url_short:<56}║{RESET}")
    print(f"{BOLD}{CYAN}{'╚' + '═' * 60 + '╝'}{RESET}")

    # ── Skor ─────────────────────────────────────────────────────────────────
    bar_filled = int(score.normalized / 5)
    bar = f"{color}{'█' * bar_filled}{'░' * (20 - bar_filled)}{RESET}"
    print(f"\n  {BOLD}PHISHING SKORU{RESET}")
    print(f"  {bar}  {color}{BOLD}{score.normalized:.0f}/100{RESET}  {score.icon} {color}{score.risk_level}{RESET}\n")

    # ── URL Özellikleri ───────────────────────────────────────────────────────
    print(f"  {BOLD}{CYAN}🔍 URL Analizi{RESET}")
    print(f"  {'─' * 50}")
    print(f"  Domain      : {BOLD}{features.domain}{RESET}")
    print(f"  Protokol    : {'🔓 HTTP (şifresiz)' if not features.has_https else '🔒 HTTPS'}")
    print(f"  TLD         : {(ORANGE if features.has_suspicious_tld else GRAY) + features.tld + RESET}")
    print(f"  URL Uzunluğu: {features.url_length} karakter")
    print(f"  Entropi     : {features.domain_entropy:.2f} {'⚠️ Yüksek' if features.domain_entropy > 3.8 else '✅ Normal'}")

    if features.has_ip:
        print(f"  {DKRED}❌ IP Adresi kullanılmış: {features.domain}{RESET}")
    if features.is_shortened:
        print(f"  {ORANGE}⚠️  URL Kısaltıcı tespit edildi{RESET}")
    if features.brand_in_subdomain:
        print(f"  {DKRED}❌ Marka subdomain'de: {features.brand_in_subdomain}{RESET}")
    if features.is_subdomain_abuse:
        print(f"  {DKRED}❌ Subdomain kötüye kullanımı tespit edildi{RESET}")
    if features.phishing_keywords:
        print(f"  {ORANGE}⚠️  Phishing kelimeler: {', '.join(features.phishing_keywords[:5])}{RESET}")

    dns_c = GREEN if features.domain_resolves else RED
    dns_t = "✅ Çözümleniyor" if features.domain_resolves else "❌ Çözümlenmiyor"
    print(f"  DNS         : {dns_c}{dns_t}{RESET}", end="")
    if features.ip_address:
        print(f"  ({features.ip_address})", end="")
    print()

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if vt_result:
        print(f"\n  {BOLD}{CYAN}🦠 VirusTotal{RESET}")
        print(f"  {'─' * 40}")
        if vt_result.get("error"):
            print(f"  {GRAY}{vt_result['error']}{RESET}")
        else:
            mal = vt_result.get("malicious", 0)
            tot = vt_result.get("total", 0)
            c   = DKRED if mal >= 5 else (RED if mal >= 2 else GREEN)
            print(f"  Tespit: {c}{mal}/{tot}{RESET} engine")

    # ── Tetiklenen Kurallar ───────────────────────────────────────────────────
    if score.triggered_rules:
        print(f"\n  {BOLD}⚠  Tespit Edilen Sinyaller ({len(score.triggered_rules)}){RESET}")
        print(f"  {'─' * 50}")
        for rule in sorted(score.triggered_rules, key=lambda r: r.score, reverse=True):
            c = DKRED if rule.score >= 25 else (RED if rule.score >= 15 else ORANGE)
            print(f"  {c}[+{rule.score:>2}] {rule.description[:55]}{RESET}")

    print(f"\n  {GRAY}Tarih: {datetime.now():%Y-%m-%d %H:%M:%S}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 62}{RESET}\n")


def print_summary_table(results: list) -> None:
    """Toplu sorgu özet tablosu."""
    print(f"\n{BOLD}{CYAN}{'═' * 68}{RESET}")
    print(f"{BOLD}{CYAN}  📊 TOPLU PHISHING ANALİZ ÖZETI{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 68}{RESET}")
    print(f"  {'URL':<45} {'Skor':>5}  Seviye")
    print(f"  {'─' * 63}")

    LEVEL_COLORS = {"SAFE": GREEN, "LOW": YELLOW, "MEDIUM": ORANGE, "HIGH": RED, "CRITICAL": DKRED}
    for score in results:
        c   = LEVEL_COLORS.get(score.risk_level, GRAY)
        url = score.url[:44] if len(score.url) > 44 else score.url
        print(f"  {url:<45} {c}{score.normalized:>5.0f}{RESET}  {c}{score.icon} {score.risk_level}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 68}{RESET}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Ana Program
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Phishing URL Dedektörü — Heuristic + VirusTotal",
        epilog="""
Örnekler:
  python main.py https://paypa1-secure.tk/login
  python main.py --demo
  python main.py --file urls.txt
  python main.py https://example.com --vt-key YOUR_VT_API_KEY
  python main.py https://suspicious.xyz --json
        """
    )
    parser.add_argument("urls",     nargs="*",          help="Analiz edilecek URL(ler)")
    parser.add_argument("--file",   metavar="FILE",     help="URL listesi dosyası (satır başına bir URL)")
    parser.add_argument("--demo",   action="store_true",help="Demo mod — örnek URL'leri test et")
    parser.add_argument("--vt-key", metavar="KEY",      help="VirusTotal API key (opsiyonel)")
    parser.add_argument("--json",   action="store_true")
    parser.add_argument("--export", metavar="FILE")
    parser.add_argument("--no-dns", action="store_true",help="DNS çözümlemesini atla (daha hızlı)")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    # URL listesi oluştur
    urls = list(args.urls)
    if args.demo:
        urls = DEMO_URLS
        if not args.quiet:
            print(f"  {YELLOW}⚠  Demo modu — {len(DEMO_URLS)} örnek URL analiz ediliyor{RESET}\n")
    if args.file:
        try:
            file_urls = Path(args.file).read_text(encoding="utf-8").splitlines()
            urls.extend(u.strip() for u in file_urls if u.strip() and not u.startswith("#"))
        except FileNotFoundError:
            print(f"  {RED}Dosya bulunamadı: {args.file}{RESET}")
            sys.exit(1)

    if not urls:
        parser.print_help()
        sys.exit(0)

    extractor = URLFeatureExtractor()
    engine    = PhishingHeuristicsEngine()

    all_scores   = []
    json_report  = []
    resolve_dns  = not args.no_dns

    for i, url in enumerate(urls):
        if i > 0:
            time.sleep(0.2)

        if not args.quiet and not args.json:
            print(f"  {CYAN}[{i+1}/{len(urls)}] Analiz ediliyor:{RESET} {url[:60]}")

        features = extractor.extract(url, resolve_dns=resolve_dns)
        score    = engine.analyze(features)

        # VirusTotal (opsiyonel)
        vt_result = None
        if args.vt_key:
            if not args.quiet:
                print(f"  ⏳ VirusTotal sorgulanıyor...")
            vt_result = check_virustotal(url, args.vt_key)
            # VT sonucunu skora ekle
            if vt_result and not vt_result.get("error"):
                mal = vt_result.get("malicious", 0)
                if mal >= 5:
                    score.normalized = min(score.normalized + 20, 100)
                elif mal >= 2:
                    score.normalized = min(score.normalized + 10, 100)

        all_scores.append(score)

        # Tek URL → tam rapor
        if len(urls) == 1 and not args.json and not args.quiet:
            print_report(features, score, vt_result)

        # JSON
        entry = score.to_dict()
        entry["features"] = features.to_dict()
        if vt_result:
            entry["virustotal"] = vt_result
        json_report.append(entry)

    # Birden fazla URL
    if len(urls) > 1 and not args.json and not args.quiet:
        sorted_scores = sorted(all_scores, key=lambda x: x.normalized, reverse=True)
        print_summary_table(sorted_scores)

    # JSON çıktı
    if args.json or args.export:
        output_data = json_report[0] if len(json_report) == 1 else {
            "analyzed_at": datetime.now().isoformat(),
            "total_urls":  len(json_report),
            "results":     json_report,
        }
        output = json.dumps(output_data, indent=2, ensure_ascii=False, default=str)
        if args.export:
            Path(args.export).write_text(output, encoding="utf-8")
            print(f"  {GREEN}✅ Rapor → {args.export}{RESET}")
        if args.json:
            print(output)


if __name__ == "__main__":
    main()
