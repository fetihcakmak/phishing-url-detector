"""
heuristics.py — Phishing URL Detector
Commit 2: phishing heuristics engine

Özellik vektöründen kural tabanlı phishing skoru üretir.
Her kural ağırlıklı puan ekler, toplam 0-100 normalize edilir.

Kural Kategorileri:
  • Alan adı anomalileri (IP kullanımı, uzun domain, tire aşımı)
  • Marka/Typosquatting saldırıları
  • URL yapı şüphelilikleri (derin path, @ sembolü)
  • İçerik keywordleri (login, verify, secure...)
  • TLD ve hosting tespiti
"""

from dataclasses import dataclass, field
from url_features import URLFeatures


# ─────────────────────────────────────────────────────────────────────────────
# Kural Tanımı
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Rule:
    name:        str
    description: str
    score:       int    # Bu kural kaç puan ekler
    triggered:   bool  = False

    def to_dict(self) -> dict:
        return {
            "rule":        self.name,
            "description": self.description,
            "score":       self.score,
            "triggered":   self.triggered,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Skor Sonucu
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PhishingScore:
    url:           str
    raw_score:     int              = 0    # Ham toplam puan
    normalized:    float            = 0.0  # 0-100 normalize
    risk_level:    str              = "SAFE"
    triggered_rules: list           = field(default_factory=list)
    all_rules:     list             = field(default_factory=list)

    @property
    def is_phishing(self) -> bool:
        return self.normalized >= 60

    @property
    def icon(self) -> str:
        levels = {
            "SAFE":     "✅",
            "LOW":      "💛",
            "MEDIUM":   "🟠",
            "HIGH":     "🔴",
            "CRITICAL": "💀",
        }
        return levels.get(self.risk_level, "❓")

    @property
    def color_code(self) -> str:
        colors = {
            "SAFE":     "\033[92m",
            "LOW":      "\033[93m",
            "MEDIUM":   "\033[33m",
            "HIGH":     "\033[91m",
            "CRITICAL": "\033[31m",
        }
        return colors.get(self.risk_level, "\033[0m")

    def to_dict(self) -> dict:
        return {
            "url":            self.url,
            "phishing_score": round(self.normalized, 1),
            "risk_level":     self.risk_level,
            "is_phishing":    self.is_phishing,
            "triggered_rules": [r.to_dict() for r in self.triggered_rules],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Heuristic Engine
# ─────────────────────────────────────────────────────────────────────────────

class PhishingHeuristicsEngine:
    """
    URL özelliklerinden kural tabanlı phishing skoru hesaplar.

    Maksimum skor: 195 puan (normalize → 100)
    """

    # ── Kural Tanımları ───────────────────────────────────────────────────────

    def _build_rules(self, f: URLFeatures) -> list[Rule]:
        """Tüm kuralları oluşturur ve tetiklenenleri işaretler."""
        rules = [

            # ─── Kritik Sinyaller (yüksek puan) ─────────────────────────────

            Rule("IP_ADDRESS_URL",
                 "Domain yerine IP adresi kullanılmış (ör: http://192.168.1.1/login)",
                 score=30,
                 triggered=f.has_ip
            ),

            Rule("BRAND_SUBDOMAIN_ABUSE",
                 f"Güvenilir marka adı subdomain'de ama farklı domain'e yönlendiriyor: "
                 f"{f.brand_in_subdomain}",
                 score=35,
                 triggered=bool(f.brand_in_subdomain) or f.is_subdomain_abuse
            ),

            Rule("SUSPICIOUS_TLD",
                 f"Oltalamada sık kullanılan ücretsiz TLD: {f.tld}",
                 score=20,
                 triggered=f.has_suspicious_tld
            ),

            Rule("NO_HTTPS",
                 "HTTP kullanıyor (HTTPS yok) — veri şifrelenmeden iletiliyor",
                 score=15,
                 triggered=not f.has_https
            ),

            Rule("AT_SYMBOL",
                 "URL'de @ sembolü var — tarayıcı @ öncesini görmezden gelir",
                 score=25,
                 triggered=f.has_at_symbol
            ),

            Rule("URL_SHORTENER",
                 "URL kısaltma servisi kullanılmış — gerçek hedef gizleniyor",
                 score=20,
                 triggered=f.is_shortened
            ),

            Rule("DOUBLE_SLASH_REDIRECT",
                 "Path'te çift slash — redirect trick'i",
                 score=15,
                 triggered=f.has_double_slash
            ),

            Rule("HEX_ENCODED_URL",
                 "URL'de hex encoding var — karakter gizleme girişimi",
                 score=15,
                 triggered=f.has_hex_encoding
            ),

            # ─── Orta Sinyaller ───────────────────────────────────────────────

            Rule("MANY_PHISHING_KEYWORDS",
                 f"Oltalama anahtar kelimeleri: {f.phishing_keywords}",
                 score=20,
                 triggered=len(f.phishing_keywords) >= 2
            ),

            Rule("ONE_PHISHING_KEYWORD",
                 f"Phishing kelimesi tespit edildi: {f.phishing_keywords[:1]}",
                 score=10,
                 triggered=len(f.phishing_keywords) == 1
            ),

            Rule("BRAND_IN_PATH",
                 f"Marka adı path'te — yanıltıcı görünüm: {f.brand_in_path}",
                 score=15,
                 triggered=bool(f.brand_in_path)
            ),

            Rule("EXCESSIVE_SUBDOMAINS",
                 f"Çok fazla subdomain ({f.num_dots} nokta) — karmaşıklık yaratıyor",
                 score=15,
                 triggered=f.num_dots >= 4
            ),

            Rule("LONG_URL",
                 f"URL çok uzun ({f.url_length} karakter) — gerçek hedefi gizliyor",
                 score=10,
                 triggered=f.url_length > 100
            ),

            Rule("VERY_LONG_URL",
                 f"URL aşırı uzun ({f.url_length} karakter)",
                 score=10,
                 triggered=f.url_length > 200
            ),

            Rule("EXCESSIVE_HYPHENS",
                 f"Domain'de çok fazla tire ({f.num_hyphens}) — meşru domain taklidi",
                 score=10,
                 triggered=f.num_hyphens >= 3
            ),

            Rule("DIGITS_IN_DOMAIN",
                 f"Domain'de çok sayıda rakam ({f.num_digits_in_domain}) — rastgele görünüm",
                 score=10,
                 triggered=f.num_digits_in_domain >= 4
            ),

            Rule("HIGH_DOMAIN_ENTROPY",
                 f"Domain entropisi yüksek ({f.domain_entropy:.2f}) — rastgele oluşturulmuş",
                 score=15,
                 triggered=f.domain_entropy > 3.8
            ),

            Rule("DEEP_PATH",
                 f"URL derinliği fazla ({f.path_depth} seviye)",
                 score=5,
                 triggered=f.path_depth >= 5
            ),

            Rule("MANY_PARAMS",
                 f"Çok fazla query parametresi ({f.num_params})",
                 score=5,
                 triggered=f.num_params >= 5
            ),

            Rule("DNS_NOT_RESOLVING",
                 "Domain DNS çözümlemesi başarısız — sahte veya çevrimdışı",
                 score=20,
                 triggered=not f.domain_resolves and not f.has_ip
            ),

            # ─── Bonus: Güvenli Sinyaller (negatif) ──────────────────────────
            # Bu kurallar tetiklenirse skoru azaltmak yerine
            # diğer kurallara bırakıyoruz (sadece bilgi amaçlı)
        ]
        return rules

    # ── Skor Hesaplama ────────────────────────────────────────────────────────

    def analyze(self, features: URLFeatures) -> PhishingScore:
        """
        URL özelliklerinden phishing skoru hesaplar.

        Normalizasyon: raw_score / max_possible * 100
        """
        result = PhishingScore(url=features.url)
        rules  = self._build_rules(features)

        # Tetiklenen kuralları topla
        raw_score     = 0
        triggered     = []
        max_possible  = sum(r.score for r in rules)

        for rule in rules:
            if rule.triggered:
                raw_score += rule.score
                triggered.append(rule)

        result.raw_score      = raw_score
        result.all_rules      = rules
        result.triggered_rules = triggered

        # 0-100 normalize
        if max_possible > 0:
            result.normalized = min(raw_score / max_possible * 100 * 1.5, 100)
        result.normalized = round(result.normalized, 1)

        # Risk seviyesi
        s = result.normalized
        if s >= 80:
            result.risk_level = "CRITICAL"
        elif s >= 60:
            result.risk_level = "HIGH"
        elif s >= 40:
            result.risk_level = "MEDIUM"
        elif s >= 20:
            result.risk_level = "LOW"
        else:
            result.risk_level = "SAFE"

        return result

    def analyze_batch(self, features_list: list) -> list:
        """Birden fazla URL'yi analiz eder, en tehlikelisi başta."""
        results = [self.analyze(f) for f in features_list]
        return sorted(results, key=lambda x: x.normalized, reverse=True)
