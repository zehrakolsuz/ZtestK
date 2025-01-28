#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import sys
from datetime import datetime
from dotenv import load_dotenv

# Kendi modüllerimizi import etme
from qsec.reconnaissance.passive_recon import PassiveReconnaissance
from qsec.reconnaissance.active_recon import ActiveReconnaissance

# Ortam değişkenlerini yükle
load_dotenv()

# Logging yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('q-sec.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def print_banner():
    """Proje giriş banner'ı"""
    banner = r"""
 ▄███████▄      ███        ▄████████    ▄████████     ███        ▄█   ▄█▄ 
██▀     ▄██ ▀█████████▄   ███    ███   ███    ███ ▀█████████▄   ███ ▄███▀ 
      ▄███▀    ▀███▀▀██   ███    █▀    ███    █▀     ▀███▀▀██   ███▐██▀   
 ▀█▀▄███▀▄▄     ███   ▀  ▄███▄▄▄       ███            ███   ▀  ▄█████▀    
  ▄███▀   ▀     ███     ▀▀███▀▀▀     ▀███████████     ███     ▀▀█████▄    
▄███▀           ███       ███    █▄           ███     ███       ███▐██▄   
███▄     ▄█     ███       ███    ███    ▄█    ███     ███       ███ ▀███▄ 
 ▀████████▀    ▄████▀     ██████████  ▄████████▀     ▄████▀     ███   ▀█▀ 
                                                                ▀                                            

===========================================================================
                ZtestK  Penetrasyon Testi Araç Seti
    
                    Gelistirici= Zehra Nur Kolsuz

===========================================================================
    """
    print(banner)

def main_menu():
    """Ana menü"""
    print_banner()
    print("\n--- ANA MENU ---")
    print("1. Pasif Keşif (Passive Reconnaissance)")
    print("2. Aktif Keşif (Active Reconnaissance)")
    print("3. Tam Tarama (Full Scan)")
    print("4. Çıkış")
    
    while True:
        try:
            secim = input("\nSeçiminizi yapın (1-4): ").strip()
            
            if secim == '4':
                print("Çıkış yapılıyor...")
                sys.exit(0)
            
            if secim not in ['1', '2', '3']:
                print("Geçersiz seçim! Lütfen 1-4 arasında bir numara girin.")
                continue
            
            target = input("Hedef alan adı veya IP'yi girin: ").strip()
            
            if not target:
                print("Hedef boş bırakılamaz!")
                continue
            
            return secim, target
        
        except KeyboardInterrupt:
            print("\nİşlem iptal edildi.")
            sys.exit(0)

def print_passive_recon_results(results):
    """Pasif keşif sonuçlarını düzenli şekilde yazdır"""
    print("\n--- Pasif Keşif Raporu ---")
    print(f"Hedef Domain: {results['passive_recon_data']['domain']}")
    print(f"IP Adresi: {results['passive_recon_data']['ip']}")
    
    # WHOIS Bilgileri
    whois = results['passive_recon_data']['whois']
    print("\nWHOIS Bilgileri:")
    print(f"Kayıt Tarihi: {whois['creation_date']}")
    print(f"Bitiş Tarihi: {whois['expiration_date']}")
    
    # Web Metadata
    web_meta = results['passive_recon_data']['web_metadata']
    print("\nWeb Sayfası Bilgileri:")
    print(f"Başlık: {web_meta['title']}")
    print(f"Sunucu: {web_meta['server'] or 'Bilinmiyor'}")
    
    # E-posta Bilgileri
    emails = web_meta['emails']
    print("\nBulunan E-postalar:")
    for email in emails:
        print(f"- {email}")

def print_active_recon_results(results):
    """Aktif keşif sonuçlarını düzenli şekilde yazdır"""
    print("\n--- Aktif Keşif Raporu ---")
    print(f"Hedef Domain: {results['active_recon_data']['domain']}")
    print(f"IP Adresi: {results['active_recon_data']['ip']}")
    
    # DNS Kayıtları
    dns_records = results['active_recon_data']['dns_records']
    print("\nDNS Kayıtları:")
    print(f"A Kayıtları: {', '.join(dns_records['A'])}")
    print(f"MX Kayıtları: {', '.join(dns_records['MX'])}")
    print(f"Name Sunucuları: {', '.join(dns_records['NS'])}")
    
    # Alt Alan Adları
    subdomains = results['active_recon_data']['subdomains']
    print("\nBulunan Alt Alan Adları:")
    for subdomain in subdomains:
        print(f"- {subdomain}")

class QSecPenetrationTestFramework:
    def __init__(self, config_path='configs/main_config.yaml'):
        try:
            self.results = {
                'timestamp': datetime.now().isoformat(),
                'target': None,
                'modules': {}
            }
        except Exception as e:
            logger.error(f"Framework başlatılırken hata: {e}")
            raise

    def passive_reconnaissance(self, target):
        try:
            passive_recon = PassiveReconnaissance(target)
            results = passive_recon.gather_information()
            self.results['modules']['passive_recon'] = results
            
            # Sonuçları yazdır
            print_passive_recon_results(results)
            
            return results
        except Exception as e:
            logger.error(f"Pasif keşif hatası: {e}")
            return None

    def active_reconnaissance(self, target):
        try:
            active_recon = ActiveReconnaissance(target)
            results = active_recon.scan_target()
            self.results['modules']['active_recon'] = results
            
            # Sonuçları yazdır
            print_active_recon_results(results)
            
            return results
        except Exception as e:
            logger.error(f"Aktif keşif hatası: {e}")
            return None

def main():
    while True:
        try:
            secim, target = main_menu()
            
            framework = QSecPenetrationTestFramework()
            
            if secim == '1':
                framework.passive_reconnaissance(target)
            elif secim == '2':
                framework.active_reconnaissance(target)
            elif secim == '3':
                framework.passive_reconnaissance(target)
                framework.active_reconnaissance(target)
            
            input("\nDevam etmek için ENTER'a basın...")
        
        except Exception as e:
            logger.error(f"Framework çalıştırılırken hata: {e}")
            input("Bir hata oluştu. Devam etmek için ENTER'a basın...")

if __name__ == '__main__':
    main()
