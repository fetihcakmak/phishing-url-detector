```
.__ .  .._. __..  .._..  ..__ 
[__)|__| | (__ |__| | |\ |[ __
|   |  |_|_.__)|  |_|_| \|[_./
.__ .___.___..___ __ .___..__..__ 
|  \[__   |  [__ /  `  |  |  |[__)
|__/[___  |  [___\__.  |  |__||  \
```

# 🎣 Phishing URL Detector

> URL'leri analiz ederek oltalama (phishing) saldırısı olup olmadığını tespit eden heuristic tabanlı güvenlik aracı.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Stdlib](https://img.shields.io/badge/Dep-Stdlib_Only-success)](./)
[![Status](https://img.shields.io/badge/Status-Active-success)](./)

---

## 📌 Proje Hakkında

20+ kurala dayalı heuristic motoru ile URL'lerin phishing olasılığını **0-100** skor ile ölçer.

**Commit Geçmişi:**
| Commit | Açıklama |
|--------|----------|
| `url feature extractor` | Domain entropi, SAN, typosquatting, keyword analizi |
| `phishing heuristics engine` | 20+ ağırlıklı kural motoru, risk seviyeleri |
| `threat feed integration and cli` | VirusTotal entegrasyonu, toplu analiz, JSON export |

---

## 🧠 Mimari

```
main.py
  ├── url_features.py   ← Özellik çıkarımı
  │     • Domain entropi (Shannon)
  │     • IP adresi kullanımı tespiti
  │     • TLD şüpheli mi? (.tk .ml .xyz)
  │     • Güvenilir marka typosquatting (paypa1, g00gle)
  │     • URL kısaltma servisi (bit.ly, tinyurl)
  │     • DNS çözümlemesi
  │
  └── heuristics.py     ← Skor motoru
        • IP_ADDRESS_URL        +30 puan
        • BRAND_SUBDOMAIN_ABUSE +35 puan
        • SUSPICIOUS_TLD        +20 puan
        • AT_SYMBOL             +25 puan
        • URL_SHORTENER         +20 puan
        • NO_HTTPS              +15 puan
        • ... 20+ kural toplam
```

**Risk Seviyeleri:**

| Skor | Seviye | Açıklama |
|------|--------|----------|
| 0-19 | ✅ SAFE | Güvenli görünüyor |
| 20-39 | 💛 LOW | Düşük risk |
| 40-59 | 🟠 MEDIUM | Şüpheli, dikkatli ol |
| 60-79 | 🔴 HIGH | Büyük ihtimalle phishing |
| 80-100 | 💀 CRITICAL | Oltalama saldırısı |

---

## 🚀 Kurulum

```bash
git clone https://github.com/fetihcakmak/phishing-url-detector.git
cd phishing-url-detector

# Standart kütüphane yeterli!
python main.py --demo
```

---

## ⚡ Kullanım

```bash
# Tek URL analizi
python main.py https://paypa1-secure-login.tk/account/verify

# Demo modu (8 örnek URL)
python main.py --demo

# Toplu analiz (dosyadan)
python main.py --file urls.txt

# VirusTotal ile birlikte
python main.py https://suspicious.xyz --vt-key YOUR_API_KEY

# JSON çıktı
python main.py https://evil-site.tk --json

# DNS çözümleme olmadan (hızlı)
python main.py https://suspicious.link --no-dns
```

---

## 📊 Örnek Çıktı

```
╔════════════════════════════════════════════════════════════╗
║  🎣 https://apple.com.evil-phishing.ml/signin             ║
╚════════════════════════════════════════════════════════════╝

  PHISHING SKORU
  ████████████████████  94/100  💀 CRITICAL

  🔍 URL Analizi
  Domain      : apple.com.evil-phishing.ml
  Protokol    : 🔒 HTTPS
  TLD         : .ml  ⚠️
  URL Uzunluğu: 42 karakter
  Entropi     : 3.91 ⚠️ Yüksek
  ❌ Marka subdomain'de: ['apple']
  ❌ Subdomain kötüye kullanımı tespit edildi
  ⚠️  Phishing kelimeler: signin
  DNS         : ✅ Çözümleniyor  (185.220.101.35)

  ⚠  Tespit Edilen Sinyaller (5)
  [+35] Güvenilir marka adı subdomain'de ama farklı domain
  [+20] Oltalamada sık kullanılan ücretsiz TLD: .ml
  [+20] Phishing kelime: signin, account
  [+15] Yüksek entropi: 3.91
  [+10] Brand marka path'te
```

---

## 📁 Dosya Yapısı

```
phishing-url-detector/
├── url_features.py   ← URL özellik çıkarımı
├── heuristics.py     ← Kural tabanlı skor motoru
├── main.py           ← CLI + VirusTotal + raporlama
└── requirements.txt  ← Stdlib only
```

---

## 🔗 İlgili Projeler

- [threat-intel-aggregator](../threat-intel-aggregator) — Şüpheli IP'yi daha derin analiz et
- [web-vulnerability-scanner](../web-vulnerability-scanner) — Web güvenlik taraması
- [ssl-tls-checker](../ssl-tls-checker) — SSL sertifikası kontrolü

---

## 📄 Lisans

Bu depo şu an bir lisans dosyası içermiyor. Kullanım koşulları için proje sahibiyle iletişime geçin.

---

*Fetih Çakmak — Cybersecurity Portfolio*
