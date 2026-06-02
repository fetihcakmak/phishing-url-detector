"""
url_features.py — Phishing URL Detector
Commit 1: url feature extractor

URL'den oltalama tespiti için özellik çıkarır:
  • Alan adı özellikleri (uzunluk, derinlik, entropi)
  • Şüpheli kelimeler ve TLD'ler
  • IP adresi kullanımı
  • URL encoding ve karakter anormallikleri
  • Redirect zinciri
"""

import re
import math
import socket
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from collections import Counter


# ─────────────────────────────────────────────────────────────────────────────
# Sabitler
# ─────────────────────────────────────────────────────────────────────────────

# Phishing'de sık kullanılan anahtar kelimeler
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "account", "verify", "secure",
    "update", "confirm", "banking", "payment", "paypal", "ebay",
    "amazon", "apple", "google", "microsoft", "netflix", "bank",
    "wallet", "crypto", "bitcoin", "password", "credential",
    "support", "helpdesk", "suspended", "locked", "unusual",
    "activity", "authenticate", "validation", "recovery",
]

# Şüpheli ücretsiz/kötüye kullanılan TLD'ler
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom ücretsiz
    ".xyz", ".top", ".club", ".online",
    ".site", ".space", ".work", ".link",
    ".click", ".download", ".stream",
}

# Güvenilir marka isimleri (typosquatting kontrolü için)
TRUSTED_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "instagram", "twitter", "netflix", "ebay", "bank", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays", "linkedin",
    "dropbox", "adobe", "steam", "discord", "telegram",
]

# URL kısaltma servisleri
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "tiny.cc", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "urlshrt.com", "shorten.com",
}


# ─────────────────────────────────────────────────────────────────────────────
# Veri Yapısı
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class URLFeatures:
    url:                  str

    # Alan adı özellikleri
    scheme:               str   = ""
    domain:               str   = ""
    tld:                  str   = ""
    subdomain:            str   = ""
    path:                 str   = ""
    query:                str   = ""

    # Sayısal özellikler
    url_length:           int   = 0
    domain_length:        int   = 0
    path_depth:           int   = 0
    num_dots:             int   = 0
    num_hyphens:          int   = 0
    num_digits_in_domain: int   = 0
    num_special_chars:    int   = 0
    num_params:           int   = 0

    # Boolean özellikler
    has_ip:               bool  = False    # IP adresi kullanımı
    has_https:            bool  = False
    is_shortened:         bool  = False    # bit.ly tarzı kısaltma
    has_at_symbol:        bool  = False    # @user trick
    has_double_slash:     bool  = False    # //redirect
    has_hex_encoding:     bool  = False    # %2F gibi
    is_subdomain_abuse:   bool  = False    # paypal.com.evil.com
    has_suspicious_tld:   bool  = False

    # Kelime özellikleri
    phishing_keywords:    list  = field(default_factory=list)
    brand_in_subdomain:   list  = field(default_factory=list)   # Typosquatting
    brand_in_path:        list  = field(default_factory=list)

    # Entropi (yüksek = rastgele = şüpheli)
    domain_entropy:       float = 0.0
    path_entropy:         float = 0.0

    # DNS
    domain_resolves:      bool  = False
    ip_address:           str   = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "url"}


# ─────────────────────────────────────────────────────────────────────────────
# Yardımcı Fonksiyonlar
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Shannon entropi — yüksek değer = daha rastgele."""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    total = len(text)
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
    return round(entropy, 3)


def _is_ip_address(host: str) -> bool:
    """Host bir IP adresi mi?"""
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        pass
    # IPv6
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (socket.error, AttributeError):
        return False


def _resolve_domain(domain: str) -> tuple[bool, str]:
    """Domain DNS çözümlemesi."""
    try:
        ip = socket.gethostbyname(domain)
        return True, ip
    except socket.gaierror:
        return False, ""


def _extract_tld(domain: str) -> tuple[str, str]:
    """
    Domain'den TLD ve ana alan adı çıkarır.
    Basit yaklaşım — public suffix list kullanmıyor.
    """
    parts = domain.split(".")
    if len(parts) >= 2:
        tld = "." + parts[-1]
        # cc-TLD: .co.uk gibi
        if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
            tld = "." + parts[-2] + "." + parts[-1]
        return tld, ".".join(parts[-2:]) if len(parts) >= 2 else domain
    return "", domain


# ─────────────────────────────────────────────────────────────────────────────
# URL Özellik Çıkarıcı
# ─────────────────────────────────────────────────────────────────────────────

class URLFeatureExtractor:
    """
    URL'den phishing tespiti için özellik vektörü çıkarır.
    """

    def extract(self, url: str, resolve_dns: bool = True) -> URLFeatures:
        # URL'yi normalize et
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        features = URLFeatures(url=url)

        # ── URL Parse ────────────────────────────────────────────────────────
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            return features

        features.scheme   = parsed.scheme
        features.domain   = parsed.netloc.lower().split(":")[0]
        features.path     = parsed.path
        features.query    = parsed.query
        features.has_https = parsed.scheme == "https"

        # ── Temel Metrikler ──────────────────────────────────────────────────
        features.url_length    = len(url)
        features.domain_length = len(features.domain)
        features.num_dots      = features.domain.count(".")
        features.num_hyphens   = features.domain.count("-")
        features.path_depth    = len([p for p in features.path.split("/") if p])
        features.num_params    = len(urllib.parse.parse_qs(features.query))
        features.num_special_chars = sum(1 for c in url if c in "@!#$%^&*(){}[]|\\<>")
        features.num_digits_in_domain = sum(1 for c in features.domain if c.isdigit())

        # ── TLD ───────────────────────────────────────────────────────────────
        tld, root_domain = _extract_tld(features.domain)
        features.tld = tld
        features.has_suspicious_tld = tld.lower() in SUSPICIOUS_TLDS

        # Subdomain
        parts = features.domain.split(".")
        if len(parts) > 2:
            features.subdomain = ".".join(parts[:-2])

        # ── IP Adresi Kullanımı ───────────────────────────────────────────────
        features.has_ip = _is_ip_address(features.domain)

        # ── URL Şüpheli Karakter Analizi ─────────────────────────────────────
        features.has_at_symbol    = "@" in url
        features.has_double_slash = "//" in parsed.path
        features.has_hex_encoding = bool(re.search(r"%[0-9a-fA-F]{2}", url))

        # ── URL Kısaltma ──────────────────────────────────────────────────────
        features.is_shortened = features.domain in URL_SHORTENERS

        # ── Phishing Kelime Analizi ───────────────────────────────────────────
        url_lower = url.lower()
        features.phishing_keywords = [
            kw for kw in PHISHING_KEYWORDS if kw in url_lower
        ]

        # ── Brand / Typosquatting Tespiti ─────────────────────────────────────
        subdomain_lower = features.subdomain.lower()
        path_lower      = features.path.lower()

        for brand in TRUSTED_BRANDS:
            # Brand subdomain'de ama root domain farklıysa şüpheli
            if brand in subdomain_lower and brand not in root_domain:
                features.brand_in_subdomain.append(brand)
            if brand in path_lower:
                features.brand_in_path.append(brand)

        # Subdomain kötüye kullanımı: paypal.com.evil.com
        if features.subdomain and any(
            b + ".com" in features.subdomain or b + ".net" in features.subdomain
            for b in TRUSTED_BRANDS
        ):
            features.is_subdomain_abuse = True

        # ── Entropi ───────────────────────────────────────────────────────────
        features.domain_entropy = _shannon_entropy(features.domain)
        features.path_entropy   = _shannon_entropy(features.path)

        # ── DNS ───────────────────────────────────────────────────────────────
        if resolve_dns and not features.has_ip:
            ok, ip = _resolve_domain(features.domain)
            features.domain_resolves = ok
            features.ip_address      = ip
        elif features.has_ip:
            features.domain_resolves = True
            features.ip_address      = features.domain

        return features
