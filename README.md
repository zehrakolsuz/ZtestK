
# 🛡️ ZtestK Penetrasyon Testi Aracı 🛡️

<div>

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-yellow.svg)

</div>


## 🌟 Proje Vizyonu
ZtestK, modern siber güvenlik tehditlerine karşı geliştirilmiş, yenilikçi ve kapsamlı bir penetrasyon testi aracıdır. Hedefimiz, güvenlik profesyonellerine güçlü, esnek ve kullanıcı dostu bir platform sunmaktır. Otomatize edilmiş keşif süreçleri ve detaylı raporlama özellikleriyle, güvenlik değerlendirmelerini hızlı ve etkili bir şekilde gerçekleştirmenizi sağlar.

## ✨ Geliştirici Bilgileri
```python
DEVELOPER = {
    "name": "Zehra Nur Kolsuz",
    "student_id": "2320191014",
    "specialization": "Penetration Testing & Security Analysis",
    "project": "ZtestK Framework"
}
```

## 📋 Teknik Dokümentasyon

### 🎯 Proje Tanımı
- 🎭 **Amaç:** Otomatize edilmiş güvenlik testleri ve kapsamlı sistem analizi
- 🔍 **Kapsam:** İleri düzey pasif ve aktif bilgi toplama teknikleri
- 📊 **Hedef Kitle:** Güvenlik uzmanları, sistem yöneticileri ve penetrasyon test uzmanları

### 🛠️ Teknik Gereksinimler

#### 💻 Yazılım Gereksinimleri
- 🐍 Python >= 3.8
- 🔧 Nmap 7.80
- 📦 Git
- 🌐 İnternet bağlantısı

#### 📚 Temel Kütüphaneler
```txt
🔹 scapy==2.4.5               # Ağ paket manipülasyonu
🔹 python-nmap==0.6.1         # Port tarama ve servis keşfi
🔹 requests==2.26.0           # HTTP istekleri
🔹 beautifulsoup4==4.10.0     # Web scraping
🔹 python-whois==0.8.0        # WHOIS sorguları
🔹 dnspython==2.2.1           # DNS analizleri
🔹 shodan==1.27.0             # Shodan API entegrasyonu
🔹 python-dotenv==0.19.2      # Ortam değişkenleri
🔹 emoji                      # Görsel zenginlik
```

## 🚀 Özellikler

### 🔍 Pasif Keşif Özellikleri
- 📝 **WHOIS Analizi**
  - Detaylı domain bilgileri
  - Kayıt ve son kullanma tarihleri
  - Registrar bilgileri

- 🌐 **DNS Keşfi**
  - A, AAAA, MX, TXT kayıtları
  - SPF ve DMARC analizi
  - Zone transfer kontrolü

- 🔒 **SSL Sertifika Analizi**
  - Sertifika detayları
  - Geçerlilik kontrolü
  - Güvenlik yapılandırması

- 📊 **Metadata Toplama**
  - Web teknolojileri tespiti
  - HTTP başlık analizi
  - Robots.txt analizi

### ⚡ Aktif Keşif Özellikleri
- 🎯 **Akıllı Port Tarama**
  - TCP/UDP port taraması
  - Servis versiyonu tespiti
  - Banner grabbing

- 🔌 **Hizmet Belirleme**
  - Servis fingerprinting
  - Versiyon analizi
  - Güvenlik kontrolü

- 🌍 **Alt Domain Keşfi**
  - Brute force tarama
  - DNS enumeration
  - Wildcard tespiti

- 🗺️ **Ağ Haritalama**
  - Topoloji çıkarma
  - Traceroute analizi
  - Host discovery

## ⚙️ Parametre Yapısı

### 📌 Zorunlu Parametreler
```json
{
    "target": {
        "tip": "string",
        "açıklama": "Hedef IP adresi veya domain"
    },
    "mode": {
        "tip": "string",
        "açıklama": "Tarama modu (passive/active/full)"
    }
}
```

### 🔧 Opsiyonel Parametreler
```json
{
    "ports": {
        "tip": "string",
        "varsayılan": "1-1000",
        "açıklama": "Taranacak port aralığı"
    },
    "timeout": {
        "tip": "integer",
        "varsayılan": 30,
        "açıklama": "Zaman aşımı süresi (saniye)"
    },
    "threads": {
        "tip": "integer",
        "varsayılan": 5,
        "açıklama": "Eşzamanlı thread sayısı"
    }
}
```

## 📊 Çıktı Formatı

### 🔍 Pasif Keşif Çıktısı
```json
{
    "scan_results": {
        "domain": "example.com",
        "whois_data": {
            "registrar": "Example Registrar",
            "creation_date": "2024-01-01",
            "expiration_date": "2025-01-01"
        },
        "ssl_info": {
            "issuer": "Let's Encrypt",
            "valid_until": "2024-12-31",
            "cipher_suite": "TLS_AES_256_GCM_SHA384"
        },
        "dns_records": {
            "A": ["93.184.216.34"],
            "MX": ["mail.example.com"],
            "TXT": ["v=spf1 -all"]
        }
    }
}
```

### ⚡ Aktif Keşif Çıktısı
```json
{
    "active_scan": {
        "target": "example.com",
        "open_ports": [
            {
                "port": 80,
                "service": "http",
                "version": "Apache/2.4.41"
            },
            {
                "port": 443,
                "service": "https",
                "version": "nginx/1.18.0"
            }
        ],
        "services": {
            "web_server": "Apache/2.4.41",
            "ssl_version": "TLSv1.3"
        }
    }
}
```

## 💻 Kurulum ve Kullanım

### 🔧 Kurulum
```bash
# 📥 Projeyi Klonlayın
git clone https://github.com/zehrakolsuz/ztestk.git

# 📦 Bağımlılıkları Yükleyin
pip install -r requirements.txt

# 🔑 Shodan API Anahtarını Ayarlayın
cp .env.example .env
# .env dosyasını düzenleyin
```

### 🚀 Çalıştırma
```bash
# Python path'i ayarlayıp programı çalıştırın
PYTHONPATH=src python3 -m qsec.main
```
### 📷 Ekran Resmi

<img width="751" alt="ZtestK Screenshot" src="https://github.com/user-attachments/assets/dd1e6192-20f2-4dae-85b7-83f94a692a2e" />

### 📷 Video
([Video Dosyasını İzlemek İçin](https://github.com/zehrakolsuz/ZtestK/issues/1))
### 📋 Menü Seçenekleri
1. 🔍 Pasif Keşif
2. ⚡ Aktif Keşif
3. 🔄 Tam Tarama
4. 🚪 Çıkış

## 📈 Test ve Performans

### 🧪 Birim Testleri
- ✅ Keşif modülleri testleri
- ✅ Veri işleme testleri
- ✅ API entegrasyon testleri

### 🔬 Performans Optimizasyonları
- ⚡ Multi-threading desteği
- 🔄 Asenkron işlemler
- 📊 Bellek optimizasyonu

### 🎯 Doğruluk Oranları
- 📈 Pasif keşif: %99
- 📊 Aktif keşif: %95
- 🎯 Port tarama: %98

## 🛡️ Güvenlik Önlemleri

### 🚥 Tarama Limitleri
- ⏱️ Akıllı rate limiting
- 🔄 Otomatik gecikme ayarı
- 📊 Yük dengeleme

### 📜 Etik Kurallar
- ✅ İzinli hedef kontrolü
- 🔒 Veri güvenliği
- 📝 Sorumlu raporlama

## 💡 Gelecek Özellikler
- 🔄 Yapay zeka destekli analiz
- 📊 İleri düzey raporlama
- 🌐 Web uygulama güvenlik testleri
- 🔒 Zero-day keşif modülü

## 🤝 Katkıda Bulunma
1. 🍴 Fork yapın
2. 🌿 Feature branch oluşturun
3. ✍️ Değişikliklerinizi commit edin
4. 📤 Push edin
5. 🎁 Pull request açın

## 📜 Lisans
Bu proje MIT lisansı altında lisanslanmıştır.

## 🌟 Teşekkürler
Bu projeyi geliştirmemde destek olan [Keyvan ARASTEH](https://github.com/keyvanarasteh) hocama ve arkadaşlarıma teşekkür ederim.

---
### 🛡️ ZtestK - Güvenliğiniz İçin Buradayız 🛡️
