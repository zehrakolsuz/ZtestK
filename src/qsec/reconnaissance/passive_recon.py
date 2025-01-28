#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import json
import re
import socket
import ssl 
import dns.resolver
import requests
import whois
import shodan
from typing import Dict, Any
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import emoji

load_dotenv(override=True)

class PassiveReconnaissance:
   def __init__(self, target: str):
       self.target = target
       self.logger = logging.getLogger(__name__)
       self.shodan_api_key = os.getenv('SHODAN_API_KEY')
       if not self.shodan_api_key:
           print("Shodan API key bulunamadı")
   
   def resolve_ip(self) -> str:
       try:
           return socket.gethostbyname(self.target)
       except socket.gaierror:
           self.logger.error(f"IP çözümlemesi başarısız: {self.target}")
           return None
   
   def whois_lookup(self) -> Dict[str, Any]:
       try:
           domain_info = whois.whois(self.target)
           return {
               'registrar': domain_info.registrar,
               'creation_date': str(domain_info.creation_date),
               'expiration_date': str(domain_info.expiration_date),
               'name_servers': domain_info.name_servers,
               'status': domain_info.status,
               'emails': domain_info.emails,
               'org': domain_info.org
           }
       except Exception as e:
           self.logger.info("WHOIS sorgusu başarıyla tamamlandı")
           return {}
   
   def shodan_search(self, ip: str) -> Dict[str, Any]:
       if not self.shodan_api_key:
           return {'message': 'API key gerekli'}
       try:
           api = shodan.Shodan(self.shodan_api_key)
           search = f'ip:{ip}'
           result = api.search(search)
           
           if result['total'] == 0:
               return {'message': 'Sonuç bulunamadı'}
               
           return {
               'total_results': result['total'],
               'matches': [{
                   'ip': match['ip_str'],
                   'ports': match.get('ports', []),
                   'hostnames': match.get('hostnames', []),
                   'os': match.get('os', ''),
                   'org': match.get('org', '')
               } for match in result['matches']]
           }
       except shodan.APIError as e:
           if 'Invalid API key' in str(e):
               return {'error': 'Geçersiz API key'}
           return {'error': str(e)}

   def get_ssl_info(self) -> Dict[str, Any]:
       try:
           context = ssl.create_default_context()
           with context.wrap_socket(socket.socket(), server_hostname=self.target) as sock:
               sock.connect((self.target, 443))
               cert = sock.getpeercert()
               return {
                   'issuer': dict(x[0] for x in cert['issuer']),
                   'expiry': cert['notAfter'],
                   'subject': dict(x[0] for x in cert['subject']),
                   'version': cert['version']
               }
       except Exception:
           return {}

   def analyze_robots(self) -> Dict[str, Any]:
       try:
           response = requests.get(f"https://{self.target}/robots.txt", timeout=5)
           return {
               'content': response.text,
               'disallowed_paths': re.findall(r'Disallow: (.*)', response.text)
           }
       except Exception:
           return {}

   def security_headers(self) -> Dict[str, Any]:
       headers_to_check = [
           'Strict-Transport-Security',
           'Content-Security-Policy',
           'X-Frame-Options',
           'X-XSS-Protection',
           'X-Content-Type-Options',
           'Referrer-Policy'
       ]
       try:
           response = requests.head(f"https://{self.target}", timeout=5)
           return {header: response.headers.get(header) for header in headers_to_check}
       except Exception:
           return {}

   def get_dns_txt(self) -> Dict[str, Any]:
       try:
           resolver = dns.resolver.Resolver()
           records = {}
           try:
               txt = resolver.resolve(self.target, 'TXT')
               records['txt'] = [str(r) for r in txt]
           except:
               records['txt'] = []
           try:
               dmarc = resolver.resolve(f"_dmarc.{self.target}", 'TXT')
               records['dmarc'] = [str(r) for r in dmarc]
           except:
               records['dmarc'] = []
           return records
       except Exception:
           return {}
   
   def gather_web_metadata(self) -> Dict[str, Any]:
       try:
           response = requests.get(f"https://{self.target}", timeout=5)
           soup = BeautifulSoup(response.text, 'html.parser')
           
           return {
               'title': soup.title.string if soup.title else None,
               'server': response.headers.get('Server'),
               'x_powered_by': response.headers.get('X-Powered-By'),
               'emails': self._extract_emails(soup),
               'meta_tags': self._extract_meta_tags(soup),
               'technologies': self._detect_technologies(response.headers, soup)
           }
       except Exception as e:
           self.logger.warning(f"Web metadata toplama hatası: {e}")
           return {}
   
   def _extract_emails(self, soup: BeautifulSoup) -> list:
       return list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', soup.get_text())))
   
   def _extract_meta_tags(self, soup: BeautifulSoup) -> dict:
       meta_tags = {}
       for tag in soup.find_all('meta'):
           name = tag.get('name', tag.get('property', ''))
           if name:
               meta_tags[name] = tag.get('content', '')
       return meta_tags
   
   def _detect_technologies(self, headers: dict, soup: BeautifulSoup) -> list:
       technologies = []
       if 'Server' in headers:
           technologies.append(headers['Server'])
       if soup.find(class_=re.compile(r'react|vue|angular')):
           technologies.append('Modern Frontend Framework')
       if soup.find(class_=re.compile(r'wp-|wordpress|drupal|joomla')):
           technologies.append('CMS Based')
       return technologies
   
   def gather_information(self) -> Dict[str, Any]:
       ip_address = self.resolve_ip()
       passive_info = {
           'domain': self.target,
           'ip': ip_address,
           'whois': self.whois_lookup(),
           'shodan': self.shodan_search(ip_address) if ip_address else {},
           'web_metadata': self.gather_web_metadata(),
           'ssl_info': self.get_ssl_info(),
           'security_headers': self.security_headers(),
           'dns_txt': self.get_dns_txt(),
           'robots_txt': self.analyze_robots()
       }
       return {
           'status': 'success',
           'passive_recon_data': passive_info
       }

def print_passive_recon_results(results):
   print(emoji.emojize("\n--- :detective: Pasif Keşif Raporu ---", language='alias'))
   print(emoji.emojize(f":globe_with_meridians: Hedef Domain: {results['passive_recon_data']['domain']}", language='alias'))
   print(emoji.emojize(f":round_pushpin: IP Adresi: {results['passive_recon_data']['ip']}", language='alias'))
   
   whois = results['passive_recon_data']['whois']
   print(emoji.emojize("\n:mag: WHOIS Bilgileri:", language='alias'))
   print(emoji.emojize(f"   :white_check_mark: Kayıt Tarihi: {whois.get('creation_date', 'Bilinmiyor')}", language='alias'))
   print(emoji.emojize(f"   :calendar: Bitiş Tarihi: {whois.get('expiration_date', 'Bilinmiyor')}", language='alias'))
   print(emoji.emojize(f"   :office: Organizasyon: {whois.get('org', 'Bilinmiyor')}", language='alias'))
   
   ssl_info = results['passive_recon_data']['ssl_info']
   if ssl_info:
       print(emoji.emojize("\n:locked: SSL Sertifika Bilgileri:", language='alias'))
       print(emoji.emojize(f"   :calendar: Bitiş Tarihi: {ssl_info.get('expiry', 'Bilinmiyor')}", language='alias'))
       print(emoji.emojize(f"   :office: Sağlayıcı: {ssl_info.get('issuer', {}).get('organizationName', 'Bilinmiyor')}", language='alias'))
   
   web_meta = results['passive_recon_data']['web_metadata']
   print(emoji.emojize("\n:globe_with_meridians: Web Sayfası Bilgileri:", language='alias'))
   print(emoji.emojize(f"   :label: Başlık: {web_meta.get('title', 'Bilinmiyor')}", language='alias'))
   print(emoji.emojize(f"   :computer: Sunucu: {web_meta.get('server', 'Bilinmiyor')}", language='alias'))
   print(emoji.emojize(f"   :wrench: Teknolojiler: {', '.join(web_meta.get('technologies', ['Bilinmiyor']))}", language='alias'))

def main():
   logging.basicConfig(level=logging.INFO)
   recon = PassiveReconnaissance('example.com')
   result = recon.gather_information()
   print_passive_recon_results(result)

if __name__ == '__main__':
   main()
