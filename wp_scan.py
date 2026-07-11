#!/usr/bin/env python3
"""
wp_scan.py - Detekce WordPressu a jeho verze na zadané URL.

Použití:
    python wp_scan.py https://example.com
    python wp_scan.py example.com --timeout 15 --json
    python wp_scan.py -f urls.txt

Skript používá pouze pasivní a běžně dostupné indikátory (meta generator,
readme.html, RSS feed, REST API, přítomnost wp-* cest). Nic neexploituje.
Používejte pouze na cílech, které vlastníte nebo máte povolení testovat.
"""

import argparse
import concurrent.futures
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
except ImportError:
    sys.exit("Chybí knihovna 'requests'. Nainstalujte: pip install requests")

# Vypneme varování o neověřeném certifikátu (scanujeme i self-signed weby).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# Regexy pro nalezení verze v různých zdrojích.
VERSION_PATTERNS = [
    re.compile(r'name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)', re.I),
    re.compile(r'<generator>\s*https?://wordpress\.org/\?v=([\d.]+)', re.I),
    re.compile(r'Version\s+([\d.]+)', re.I),          # readme.html
    re.compile(r'\?ver=([\d.]+)', re.I),              # asset query stringy (méně spolehlivé)
]

# Obecné indikátory, že jde o WordPress (nezávisle na verzi).
WP_INDICATORS = [
    "wp-content", "wp-includes", "wp-json", "w/wp-login.php",
    'name="generator" content="WordPress',
]


@dataclass
class ScanResult:
    url: str
    is_wordpress: bool = False
    version: str | None = None
    version_source: str | None = None
    confidence: str = "none"           # none | low | medium | high
    indicators: list[str] = field(default_factory=list)
    error: str | None = None


def build_session(timeout: int) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    retries = Retry(total=2, backoff_factor=0.4,
                    status_forcelist=(500, 502, 503, 504))
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.request_timeout = timeout  # uložíme si pro pohodlí
    return session


def normalize_url(raw: str) -> str:
    if not urlparse(raw).scheme:
        raw = "https://" + raw
    return raw.rstrip("/") + "/"


def fetch(session: requests.Session, url: str, timeout: int):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True,
                           verify=False)
    except requests.RequestException:
        return None


def extract_version(text: str) -> str | None:
    for pattern in VERSION_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(1)
    return None


def scan(url: str, timeout: int = 10) -> ScanResult:
    url = normalize_url(url)
    session = build_session(timeout)
    result = ScanResult(url=url)

    # 1) Hlavní stránka - meta generator + obecné indikátory.
    home = fetch(session, url, timeout)
    if home is None:
        result.error = "Cíl je nedostupný (timeout / DNS / connection error)."
        return result

    body = home.text
    for ind in WP_INDICATORS:
        if ind.lower() in body.lower():
            result.is_wordpress = True
            result.indicators.append(f"homepage: {ind}")

    ver = extract_version(body)
    if ver:
        result.version, result.version_source = ver, "homepage meta generator"

    # 2) Zdroje, které často verzi obsahují (v pořadí spolehlivosti).
    probes = [
        ("readme.html", "readme.html"),
        ("feed/", "RSS feed generator"),
        ("wp-links-opml.php", "OPML generator"),
        ("wp-json/", "REST API"),
    ]
    for path, source in probes:
        # Pokud už máme spolehlivou verzi z generatoru, další zdroje jen potvrzují.
        resp = fetch(session, urljoin(url, path), timeout)
        if resp is None or resp.status_code >= 400:
            continue

        text = resp.text
        # REST API root jasně prozradí WP i bez verze.
        if path == "wp-json/" and ("wp/v2" in text or "\"namespaces\"" in text):
            result.is_wordpress = True
            result.indicators.append("REST API /wp-json/ dostupné")

        if not result.version:
            v = extract_version(text)
            if v:
                result.version, result.version_source = v, source
                result.is_wordpress = True
                result.indicators.append(f"{path}: nalezena verze")

    # 3) Ověření existence typických WP cest (jen HEAD/GET status).
    for path in ("wp-login.php", "wp-admin/", "wp-content/"):
        resp = fetch(session, urljoin(url, path), timeout)
        if resp is not None and resp.status_code < 400:
            result.is_wordpress = True
            result.indicators.append(f"cesta dostupná: /{path}")

    # 4) Stanovení míry jistoty.
    if result.version:
        result.confidence = "high"
        result.is_wordpress = True
    elif result.is_wordpress and len(result.indicators) >= 2:
        result.confidence = "medium"
    elif result.is_wordpress:
        result.confidence = "low"

    return result


def print_human(r: ScanResult) -> None:
    line = "=" * 60
    print(line)
    print(f"Cíl: {r.url}")
    if r.error:
        print(f"  [!] {r.error}")
        print(line)
        return
    print(f"  WordPress:  {'ANO' if r.is_wordpress else 'ne / nedetekováno'}")
    if r.version:
        print(f"  Verze:      {r.version}  (zdroj: {r.version_source})")
    elif r.is_wordpress:
        print("  Verze:      nezjištěna (skrytá nebo odstraněný generator)")
    print(f"  Jistota:    {r.confidence}")
    if r.indicators:
        print("  Indikátory:")
        for ind in r.indicators:
            print(f"    - {ind}")
    print(line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detekce WordPressu a jeho verze na zadané URL.")
    parser.add_argument("url", nargs="?", help="cílová URL (např. example.com)")
    parser.add_argument("-f", "--file",
                        help="soubor se seznamem URL (jedna na řádek)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="timeout v sekundách (výchozí 10)")
    parser.add_argument("-w", "--workers", type=int, default=5,
                        help="počet paralelních vláken při -f (výchozí 5)")
    parser.add_argument("--json", action="store_true",
                        help="výstup ve formátu JSON")
    args = parser.parse_args()

    targets: list[str] = []
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                targets = [ln.strip() for ln in fh if ln.strip()
                           and not ln.startswith("#")]
        except OSError as e:
            sys.exit(f"Nelze číst soubor: {e}")
    elif args.url:
        targets = [args.url]
    else:
        parser.error("Zadejte URL nebo použijte -f soubor.")

    results: list[ScanResult] = []
    if len(targets) == 1:
        results.append(scan(targets[0], args.timeout))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(scan, t, args.timeout): t for t in targets}
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result())

    if args.json:
        print(json.dumps([asdict(r) for r in results],
                         ensure_ascii=False, indent=2))
    else:
        for r in results:
            print_human(r)


if __name__ == "__main__":
    main()
