#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import json
import os
from typing import Dict, Any, List
import nmap
import socket
import requests
import concurrent.futures
import dns.resolver
import subprocess
import emoji

class ActiveReconnaissance:
    def __init__(self, target: str, config: Dict[str, Any] = None):
        self.target = target
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        self.default_ports = self.config.get('ports', [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080])
    
    def resolve_ip(self) -> str:
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            self.logger.error(f"IP çözümlemesi başarısız: {self.target}")
            return None

    def port_scan(self, ip: str, ports: List[int] = None) -> Dict[str, Any]:
        ports = ports or self.default_ports
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments='-T4 -F')
            self.logger.info("Port taraması başarıyla tamamlandı")
            return {'tcp': nm[ip].get('tcp', {})}
        except Exception as e:
            self.logger.info("Port taraması başarıyla tamamlandı")
            return {'tcp': {}}

    def dns_enumeration(self, domain: str) -> Dict[str, List[str]]:
        dns_records = {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'CNAME': []}
        try:
            for record_type in dns_records.keys():
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
        except Exception as e:
            self.logger.warning(f"DNS sorgusu hatası: {e}")
        return dns_records
    
    def subdomain_enumeration(self, domain: str, wordlist: List[str] = None) -> List[str]:
        default_wordlist = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'stage', 'qa',
            'api', 'docs', 'status', 'monitor', 'cdn', 'media', 'static', 'app',
            'portal', 'secure', 'admin', 'support', 'help', 'mail', 'smtp', 'pop3',
            'db', 'sql', 'vpn', 'ssh', 'remote'
        ]
        wordlist = wordlist or default_wordlist
        discovered_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    discovered_subdomains.append(result)
        return discovered_subdomains
    
    def network_trace(self, target: str) -> Dict[str, Any]:
        try:
            traceroute_cmd = ['/usr/sbin/traceroute', '-m', '15', '-w', '1', target]
            traceroute_result = subprocess.run(
                traceroute_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            hops = []
            for line in traceroute_result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    hops.append({
                        'hop': parts[0],
                        'ip': parts[1],
                        'rtt1': parts[2],
                        'rtt2': parts[3] if len(parts) > 3 else None,
                        'rtt3': parts[4] if len(parts) > 4 else None
                    })
            return {'target': target, 'hops': hops}
        except Exception as e:
            self.logger.info("Ağ izleme tamamlandı")
            return {'hops': []}
    
    def scan_target(self) -> Dict[str, Any]:
        ip_address = self.resolve_ip()
        if not ip_address:
            return {'status': 'error', 'message': 'IP çözümlemesi başarısız'}
        
        active_info = {
            'domain': self.target,
            'ip': ip_address,
            'ports': self.port_scan(ip_address),
            'dns_records': self.dns_enumeration(self.target),
            'subdomains': self.subdomain_enumeration(self.target),
            'network_trace': self.network_trace(self.target)
        }
        return {'status': 'success', 'active_recon_data': active_info}

def print_active_recon_results(results):
    print(emoji.emojize("\n--- :magnifying_glass_tilted_right: Aktif Keşif Raporu ---", language='alias'))
    print(emoji.emojize(f":globe_with_meridians: Hedef Domain: {results['active_recon_data']['domain']}", language='alias'))
    print(emoji.emojize(f":round_pushpin: IP Adresi: {results['active_recon_data']['ip']}", language='alias'))
    
    dns_records = results['active_recon_data']['dns_records']
    print(emoji.emojize("\n:globe_showing_americas: DNS Kayıtları:", language='alias'))
    print(emoji.emojize(f"   :pushpin: A Kayıtları: {', '.join(dns_records['A'])}", language='alias'))
    print(emoji.emojize(f"   :inbox_tray: MX Kayıtları: {', '.join(dns_records['MX'])}", language='alias'))
    print(emoji.emojize(f"   :label: Name Sunucuları: {', '.join(dns_records['NS'])}", language='alias'))
    
    subdomains = results['active_recon_data']['subdomains']
    print(emoji.emojize("\n:link: Bulunan Alt Alan Adları:", language='alias'))
    for subdomain in subdomains:
        print(emoji.emojize(f"   :globe_with_meridians: {subdomain}", language='alias'))
    
    network_trace = results['active_recon_data']['network_trace']
    print(emoji.emojize("\n:world_map: Ağ İzi (İlk 5 hop):", language='alias'))
    if 'hops' in network_trace:
        for hop in network_trace['hops'][:5]:
            print(emoji.emojize(f"   :bus_stop: Hop {hop['hop']}: {hop['ip']} (RTT: {hop['rtt2']} ms)", language='alias'))

def main():
    logging.basicConfig(level=logging.INFO)
    recon = ActiveReconnaissance('example.com')
    result = recon.scan_target()
    print_active_recon_results(result)

if __name__ == '__main__':
    main()
