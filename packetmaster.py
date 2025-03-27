#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PacketMaster - Gelişmiş Ağ Paket Yakalama ve Analiz Aracı
Penetrasyon Testi ve Güvenlik Analizi Odaklı Sürüm

Kullanım:
    sudo python3 packetmaster.py [options]

Özellikler:
  - Derinlemesine Paket Yakalama ve Analiz
  - Hassas Veri Sızıntısı Tespiti
  - Şifrelenmiş Trafik Analizi
  - Ağ İzleme ve Keşif
  - Gelişmiş Filtreleme Yöntemleri
  - WiFi Ağları İzleme
"""

import os
import re
import sys
import json
import time
import signal
import base64
import socket
import struct
import argparse
import ipaddress
import threading
import binascii
import subprocess
from datetime import datetime
from collections import defaultdict, Counter, OrderedDict
from typing import Dict, List, Any, Optional, Set, Tuple, Union

try:
    from scapy.all import *
    from scapy.layers.http import *
    from scapy.layers.inet import *
    from scapy.layers.dns import *
except ImportError:
    print("[-] Scapy kütüphanesi bulunamadı. Lütfen 'pip install scapy' komutunu çalıştırın.")
    sys.exit(1)

# ===== Terminal Renkleri ve UI =====

class Colors:
    """Terminal renkleri ve stil kodları"""
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    ENDC = '\033[0m'

class UI:
    """UI yardımcıları"""
    
    @staticmethod
    def print_banner():
        """Program başlık ekranını göster"""
        banner = f"""
{Colors.BRIGHT_CYAN}{Colors.BOLD}
██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝███████║██║     █████╔╝ █████╗     ██║   ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Colors.ENDC}{Colors.BRIGHT_RED}{Colors.BOLD}          Gelişmiş Ağ Paket Yakalama ve Analiz Aracı - Pentest Sürümü{Colors.ENDC}
"""
        print(banner)
        
    @staticmethod
    def print_info(message):
        """Bilgi mesajı göster"""
        print(f"{Colors.BLUE}[*] {message}{Colors.ENDC}")
        
    @staticmethod
    def print_success(message):
        """Başarı mesajı göster"""
        print(f"{Colors.GREEN}[+] {message}{Colors.ENDC}")
        
    @staticmethod
    def print_warning(message):
        """Uyarı mesajı göster"""
        print(f"{Colors.YELLOW}[!] {message}{Colors.ENDC}")
        
    @staticmethod
    def print_error(message):
        """Hata mesajı göster"""
        print(f"{Colors.RED}[-] {message}{Colors.ENDC}")
        
    @staticmethod
    def print_critical(message):
        """Kritik mesaj göster"""
        print(f"{Colors.BOLD}{Colors.RED}[!!] {message}{Colors.ENDC}")
        
    @staticmethod
    def print_highlight(message):
        """Vurgulu mesaj göster"""
        print(f"{Colors.BOLD}{Colors.MAGENTA}>>> {message}{Colors.ENDC}")
    
    @staticmethod
    def print_section(title):
        """Bölüm başlığı göster"""
        width = 80
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_CYAN}" + "=" * width)
        print(f" {title} ".center(width, "="))
        print("=" * width + f"{Colors.ENDC}")

# ===== Analiz Modülleri =====

class PacketAnalyzer:
    """Paket analiz motoru sınıfı"""
    
    def __init__(self, keywords=None, regex_patterns=None, sensitive_info=True, verbose=False):
        """Analiz motorunu yapılandır"""
        self.keywords = keywords or []
        self.regex_patterns = regex_patterns or []
        self.sensitive_info = sensitive_info
        self.verbose = verbose
        
        # Düzenli ifadeleri derle
        self.compiled_regex = []
        for pattern in self.regex_patterns:
            try:
                self.compiled_regex.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                UI.print_error(f"Geçersiz regex deseni: {pattern}")
        
        # Varsayılan regex'ler
        if self.sensitive_info:
            self._add_sensitive_data_regexes()
    
    def _add_sensitive_data_regexes(self):
        """Hassas veri tespiti için düzenli ifadeler ekle"""
        # Kredi kartı regex
        self.compiled_regex.append(re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35[0-9]{3})[0-9]{11})\b'))
        
        # E-posta regex
        self.compiled_regex.append(re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'))
        
        # API Anahtarı regex çeşitleri
        self.compiled_regex.append(re.compile(r'\b(?:api[_-]?key|apikey|token|secret|access[_-]?key)(?:\s*[:=]\s*|\s+)["\'`]?([A-Za-z0-9]{16,})["\'`]?\b', re.IGNORECASE))
        
        # AWS anahtarları
        self.compiled_regex.append(re.compile(r'\b(?:AKIA[0-9A-Z]{16})\b'))
        
        # Özel anahtar başlangıcı
        self.compiled_regex.append(re.compile(r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----'))
        
        # JWT token
        self.compiled_regex.append(re.compile(r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'))
        
        # IP Adresi
        self.compiled_regex.append(re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'))
        
        # Sosyal Güvenlik Numarası (SSN)
        self.compiled_regex.append(re.compile(r'\b\d{3}-\d{2}-\d{4}\b'))
        
    def process_packet(self, packet):
        """Bir paketi analiz et ve bilgileri çıkar"""
        # Temel paket bilgisi
        packet_info = self._extract_base_info(packet)
        
        # İçerik analizi (eğer veri varsa)
        if packet.haslayer(Raw):
            try:
                # Ham veriyi çıkar
                payload = packet[Raw].load
                
                # Önce binary olarak analiz et
                binary_results = self._analyze_binary_payload(payload, packet_info)
                if binary_results:
                    packet_info.update(binary_results)
                
                # Sonra metin olarak analiz et
                try:
                    text_payload = payload.decode('utf-8', errors='ignore')
                    text_results = self._analyze_text_payload(text_payload, packet_info)
                    if text_results:
                        packet_info.update(text_results)
                except:
                    pass
                    
            except Exception as e:
                if self.verbose:
                    UI.print_error(f"İçerik analiz hatası: {str(e)}")
        
        # Protokol bazlı özel analizler
        if packet.haslayer(DNS):
            dns_info = self._analyze_dns(packet)
            packet_info.update(dns_info)
            
        elif packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            http_info = self._analyze_http(packet)
            packet_info.update(http_info)
            
        # WiFi paketi analizi (eğer 802.11 paketi ise)
        if Dot11 in packet:
            wifi_info = self._analyze_wifi(packet)
            packet_info.update(wifi_info)
            
        return packet_info
        
    def _extract_base_info(self, packet):
        """Paketten temel bilgileri çıkar"""
        # Zaman damgası
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Paket boyutu
        packet_size = len(packet)
        
        # Temel paket bilgileri 
        packet_info = {
            "timestamp": timestamp,
            "size": packet_size,
            "protocol": "UNKNOWN",
            "layers": [layer.__name__ for layer in packet.layers()],
            "raw_packet": packet  # İleri analiz için ham paketi sakla
        }
        
        # 802.11 WiFi paketi mi?
        if Dot11 in packet:
            packet_info["protocol"] = "WiFi"
            if packet.haslayer(Dot11Beacon):
                packet_info["wifi_type"] = "Beacon"
            elif packet.haslayer(Dot11ProbeReq):
                packet_info["wifi_type"] = "Probe Request"
            elif packet.haslayer(Dot11ProbeResp):
                packet_info["wifi_type"] = "Probe Response"
            elif packet.haslayer(Dot11Auth):
                packet_info["wifi_type"] = "Authentication"
            elif packet.haslayer(Dot11AssoReq):
                packet_info["wifi_type"] = "Association Request"
            elif packet.haslayer(Dot11AssoResp):
                packet_info["wifi_type"] = "Association Response"
            elif packet.haslayer(Dot11Deauth):
                packet_info["wifi_type"] = "Deauthentication"
            else:
                packet_info["wifi_type"] = "Data"
                
            # MAC adresleri
            src_mac = packet[Dot11].addr2
            dst_mac = packet[Dot11].addr1
            bssid = packet[Dot11].addr3
            
            packet_info["src_mac"] = src_mac if src_mac else "N/A"
            packet_info["dst_mac"] = dst_mac if dst_mac else "N/A" 
            packet_info["bssid"] = bssid if bssid else "N/A"
        
        # Normal IP paketi mi?
        elif IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            # Protokol adını belirle
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
            
            # Port bilgisi
            src_port = dst_port = "N/A"
            if proto_name == "TCP" and packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # TCP bayraklarını kontrol et
                flags = []
                if packet[TCP].flags & 0x01: flags.append("FIN")
                if packet[TCP].flags & 0x02: flags.append("SYN")
                if packet[TCP].flags & 0x04: flags.append("RST")
                if packet[TCP].flags & 0x08: flags.append("PSH")
                if packet[TCP].flags & 0x10: flags.append("ACK")
                if packet[TCP].flags & 0x20: flags.append("URG")
                
                packet_info["tcp_flags"] = flags
                
            elif proto_name == "UDP" and packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            packet_info["protocol"] = proto_name
            packet_info["src_ip"] = src_ip
            packet_info["dst_ip"] = dst_ip
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            
            # Servis bilgisi
            service = self._get_service_info(src_port, dst_port, proto_name)
            if service:
                packet_info["service"] = service
                
            # HTTP/HTTPS tanımlama
            if proto_name == "TCP":
                if dst_port == 80 or src_port == 80 or dst_port == 8080 or src_port == 8080:
                    packet_info["is_http"] = True
                elif dst_port == 443 or src_port == 443 or dst_port == 8443 or src_port == 8443:
                    packet_info["is_https"] = True
        
        # ARP paketi mi?
        elif ARP in packet:
            packet_info["protocol"] = "ARP"
            packet_info["src_ip"] = packet[ARP].psrc
            packet_info["dst_ip"] = packet[ARP].pdst
            packet_info["src_mac"] = packet[ARP].hwsrc
            packet_info["dst_mac"] = packet[ARP].hwdst
            
            # ARP işlemini belirle
            if packet[ARP].op == 1:
                packet_info["arp_type"] = "who-has"
            elif packet[ARP].op == 2:
                packet_info["arp_type"] = "is-at"
                
        # Ethernet paketi mi?
        elif Ether in packet:
            packet_info["protocol"] = "Ethernet"
            packet_info["src_mac"] = packet[Ether].src
            packet_info["dst_mac"] = packet[Ether].dst
        
        return packet_info
    
    def _analyze_binary_payload(self, payload, packet_info):
        """İkili veriyi analiz et"""
        results = {}
        
        # Bazı özel binary örüntüler
        
        # 1. SSL/TLS handshake
        if payload.startswith(b'\x16\x03'):
            results["tls_detected"] = True
            
            # TLS sürümünü çıkarmaya çalış
            if len(payload) > 5:
                # Client Hello (1) veya Server Hello (2) paketi mi?
                if payload[5] == 1:
                    results["tls_type"] = "Client Hello"
                elif payload[5] == 2:
                    results["tls_type"] = "Server Hello"
        
        # 2. JPEG/PNG/GIF gibi resim dosyaları
        if payload.startswith(b'\xff\xd8\xff'):
            results["content_type"] = "JPEG Image"
        elif payload.startswith(b'\x89PNG\r\n\x1a\n'):
            results["content_type"] = "PNG Image"
        elif payload.startswith(b'GIF87a') or payload.startswith(b'GIF89a'):
            results["content_type"] = "GIF Image"
        
        # 3. ZIP/Sıkıştırılmış dosyalar
        if payload.startswith(b'PK\x03\x04'):
            results["content_type"] = "ZIP Archive"
        
        # 4. PDF dosyaları
        if payload.startswith(b'%PDF'):
            results["content_type"] = "PDF Document"
        
        # 5. Binary içinde hex encoded hassas veriler arama
        try:
            hex_payload = binascii.hexlify(payload).decode('ascii')
            for pattern in self.compiled_regex:
                matches = pattern.findall(hex_payload)
                if matches:
                    if "binary_matches" not in results:
                        results["binary_matches"] = []
                    for match in matches:
                        results["binary_matches"].append({
                            "pattern": str(pattern.pattern),
                            "value": match
                        })
        except:
            pass
        
        return results
        
    def _analyze_text_payload(self, text, packet_info):
        """Metin içeriğini analiz et"""
        results = {}
        
        # Anahtar kelime kontrolü
        if self.keywords:
            keyword_matches = []
            for keyword in self.keywords:
                if keyword.lower() in text.lower():
                    context = self._get_context(text, keyword)
                    keyword_matches.append({
                        "keyword": keyword,
                        "context": context,
                    })
            
            if keyword_matches:
                results["keyword_matches"] = keyword_matches
        
        # Regex kontrolleri
        regex_matches = []
        for pattern in self.compiled_regex:
            matches = pattern.findall(text)
            if matches:
                for match in matches:
                    # Match bir tuple ise, ilk öğesini kullan (grup yakalandıysa)
                    if isinstance(match, tuple) and match:
                        match = match[0]
                        
                    # Hassas verileri maskele
                    masked_match = self._mask_sensitive_data(match, pattern.pattern)
                    context = self._get_context(text, match)
                    
                    regex_matches.append({
                        "pattern": str(pattern.pattern),
                        "value": masked_match,
                        "context": context
                    })
        
        if regex_matches:
            results["regex_matches"] = regex_matches
            
        # HTTP POST verilerini algıla
        if packet_info.get("is_http") and "POST" in text[:20]:
            post_data = self._extract_post_data(text)
            if post_data:
                results["http_post_data"] = post_data
                
        # Kimlik doğrulama bilgilerini algıla
        auth_data = self._extract_auth_data(text, packet_info)
        if auth_data:
            results["auth_data"] = auth_data
        
        return results
        
    def _get_context(self, text, keyword, context_size=50):
        """Anahtar kelime veya eşleşme etrafındaki metni al"""
        if isinstance(keyword, bytes):
            keyword = keyword.decode('utf-8', errors='ignore')
            
        keyword_index = text.lower().find(str(keyword).lower())
        if keyword_index == -1:
            return ""
        
        # Bağlam sınırlarını belirle
        start = max(0, keyword_index - context_size)
        end = min(len(text), keyword_index + len(str(keyword)) + context_size)
        
        # Bağlamı çıkar
        context = text[start:end]
        
        # Kırpılma durumunda belirtme
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."
            
        # Anahtar kelimeyi vurgula
        try:
            pattern = re.compile(re.escape(str(keyword)), re.IGNORECASE)
            context = pattern.sub(f"{Colors.BOLD}{Colors.RED}\\g<0>{Colors.ENDC}", context)
        except:
            pass
            
        return context
    
    def _mask_sensitive_data(self, data, pattern):
        """Hassas veriyi maskele"""
        # Kredi kartları
        if "4[0-9]{12}" in pattern or "5[1-5][0-9]{14}" in pattern:
            if len(data) > 6:
                return data[:6] + "*" * (len(data) - 10) + data[-4:]
                
        # API Anahtarları, Token'lar vb.
        elif "api[_-]?key" in pattern or "token" in pattern or "secret" in pattern:
            if len(data) > 8:
                return data[:4] + "*" * (len(data) - 8) + data[-4:]
                
        # E-posta
        elif "@" in data and "." in data:
            parts = data.split("@")
            if len(parts) == 2 and len(parts[0]) > 2:
                username = parts[0][:2] + "*" * (len(parts[0]) - 2)
                return f"{username}@{parts[1]}"
                
        # Herhangi bir hassas veri
        elif len(data) > 8:
            return data[:3] + "*" * (len(data) - 6) + data[-3:]
            
        return data
        
    def _extract_post_data(self, text):
        """HTTP POST formunu ayıkla"""
        try:
            # POST verisini bul
            post_data = {}
            
            # İki yaklaşım: URL kodlu form ve JSON
            if "\r\n\r\n" in text:
                body = text.split("\r\n\r\n", 1)[1]
                
                # JSON formatı kontrol et
                if body.strip().startswith("{") and body.strip().endswith("}"):
                    try:
                        json_data = json.loads(body)
                        return {"format": "json", "data": json_data}
                    except:
                        pass
                        
                # URL kodlu form
                params = body.split("&")
                for param in params:
                    if "=" in param:
                        key, value = param.split("=", 1)
                        post_data[key] = value
                        
                if post_data:
                    return {"format": "urlencoded", "data": post_data}
        except:
            pass
            
        return None
        
    def _extract_auth_data(self, text, packet_info):
        """Kimlik doğrulama bilgilerini çıkar"""
        auth_data = []
        
        # HTTP Basic Auth
        basic_auth_match = re.search(r'Authorization:\s+Basic\s+([A-Za-z0-9+/=]+)', text)
        if basic_auth_match:
            try:
                auth_b64 = basic_auth_match.group(1)
                decoded = base64.b64decode(auth_b64).decode('utf-8')
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
                    auth_data.append({
                        "type": "HTTP Basic Auth",
                        "username": username,
                        "password": password
                    })
            except:
                pass
        
        # Form tabanlı giriş
        username_patterns = [
            r'(?:username|user|email|login|kullanici|kullaniciadi)[\s:=]+["\']*([^"\'\s&]+)',
            r'"(?:username|user|email|login|kullanici|kullaniciadi)"\s*:\s*"([^"]+)"'
        ]
        
        password_patterns = [
            r'(?:password|pass|passwd|pword|sifre)[\s:=]+["\']*([^"\'\s&]+)',
            r'"(?:password|pass|passwd|pword|sifre)"\s*:\s*"([^"]+)"'
        ]
        
        for u_pattern in username_patterns:
            u_match = re.search(u_pattern, text, re.IGNORECASE)
            if u_match:
                username = u_match.group(1)
                
                # Kullanıcı adı bulundu, şimdi şifre ara
                for p_pattern in password_patterns:
                    p_match = re.search(p_pattern, text, re.IGNORECASE)
                    if p_match:
                        password = p_match.group(1)
                        auth_data.append({
                            "type": "Form Login",
                            "username": username,
                            "password": password
                        })
                        break
        
        # OAuth token
        oauth_match = re.search(r'(?:Bearer|access_token|token)[\s:=]+["\']*([A-Za-z0-9._-]+)', text, re.IGNORECASE)
        if oauth_match:
            token = oauth_match.group(1)
            auth_data.append({
                "type": "OAuth Token",
                "token": self._mask_sensitive_data(token, "token")
            })
            
        return auth_data if auth_data else None
    
    def _get_service_info(self, src_port, dst_port, proto):
        """Port numaralarından servis bilgisini belirle"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
            67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 
            123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 
            143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS",
            445: "SMB", 465: "SMTPS", 514: "Syslog", 636: "LDAPS", 993: "IMAPS", 
            995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 
            5901: "VNC", 5985: "WinRM", 8000: "HTTP-Alt", 8008: "HTTP", 
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        
        src_service = common_ports.get(src_port, "") if isinstance(src_port, int) else ""
        dst_service = common_ports.get(dst_port, "") if isinstance(dst_port, int) else ""
        
        if src_service and dst_service:
            if src_service == dst_service:
                return src_service
            return f"{src_service} -> {dst_service}"
        elif src_service:
            return src_service
        elif dst_service:
            return dst_service
            
        return ""
    
    def _analyze_dns(self, packet):
            """DNS paketini analiz et"""
            results = {}
            
            try:
                dns = packet[DNS]
                
                # Sorgu mu cevap mı?
                if dns.qr == 0:
                    results["dns_type"] = "Query"
                else:
                    results["dns_type"] = "Response"
                    
                # Sorgu detayları
                if dns.qd:
                    query_name = dns.qd.qname.decode('utf-8')
                    if query_name.endswith('.'):
                        query_name = query_name[:-1]
                    results["dns_query"] = query_name
                    
                    # Sorgu tipi
                    qtype = dns.qd.qtype
                    qtypes = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
                    results["dns_query_type"] = qtypes.get(qtype, str(qtype))
                    
                # Cevap detayları
                if dns.qr == 1 and dns.ancount > 0:
                    answers = []
                    for i in range(dns.ancount):
                        rdata = dns.an[i].rdata
                        if isinstance(rdata, bytes):
                            try:
                                if dns.an[i].type == 1:  # A kaydı
                                    ip = socket.inet_ntoa(rdata)
                                    answers.append({"type": "A", "data": ip})
                                elif dns.an[i].type == 5:  # CNAME
                                    cname = rdata.decode('utf-8')
                                    if cname.endswith('.'):
                                        cname = cname[:-1]
                                    answers.append({"type": "CNAME", "data": cname})
                                elif dns.an[i].type == 28:  # AAAA
                                    ipv6 = socket.inet_ntop(socket.AF_INET6, rdata)
                                    answers.append({"type": "AAAA", "data": ipv6})
                                else:
                                    answers.append({"type": str(dns.an[i].type), "data": str(rdata)})
                            except:
                                answers.append({"type": str(dns.an[i].type), "data": str(rdata)})
                        else:
                            answers.append({"type": str(dns.an[i].type), "data": str(rdata)})
                    
                    if answers:
                        results["dns_answers"] = answers
            except Exception as e:
                if self.verbose:
                    UI.print_error(f"DNS analiz hatası: {str(e)}")
                    
            return results
        
    def _analyze_http(self, packet):
        """HTTP paketini analiz et"""
        results = {}
        
        # HTTP İstek
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            results["http_type"] = "Request"
            
            # Metot ve path
            if hasattr(http, 'Method'):
                results["http_method"] = http.Method.decode('utf-8')
            if hasattr(http, 'Path'):
                results["http_path"] = http.Path.decode('utf-8')
                
            # Host ve User-Agent
            if hasattr(http, 'Host'):
                results["http_host"] = http.Host.decode('utf-8')
            if hasattr(http, 'User_Agent'):
                results["http_user_agent"] = http.User_Agent.decode('utf-8')
                
            # HTTP başlıkları
            headers = {}
            for field in http.fields:
                if field != 'Method' and field != 'Path' and field != 'Http_Version':
                    try:
                        headers[field] = getattr(http, field).decode('utf-8')
                    except:
                        headers[field] = str(getattr(http, field))
            
            if headers:
                results["http_headers"] = headers
                
        # HTTP Yanıt
        elif packet.haslayer(HTTPResponse):
            http = packet[HTTPResponse]
            results["http_type"] = "Response"
            
            # Durum kodu
            if hasattr(http, 'Status_Code'):
                results["http_status"] = int(http.Status_Code)
                
            # İçerik tipi
            if hasattr(http, 'Content_Type'):
                results["http_content_type"] = http.Content_Type.decode('utf-8')
                
            # HTTP başlıkları
            headers = {}
            for field in http.fields:
                if field != 'Status_Code' and field != 'Reason_Phrase' and field != 'Http_Version':
                    try:
                        headers[field] = getattr(http, field).decode('utf-8')
                    except:
                        headers[field] = str(getattr(http, field))
            
            if headers:
                results["http_headers"] = headers
                
        # Bilinen HTTP portu üzerinde ham TCP paketi
        elif 'is_http' in packet and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # İstek mi yanıt mı kontrol et
                if payload.startswith("GET ") or payload.startswith("POST ") or payload.startswith("PUT ") or payload.startswith("DELETE "):
                    results["http_type"] = "Request"
                    
                    # Metot ve yolu çıkar
                    first_line = payload.split("\r\n")[0]
                    parts = first_line.split(" ")
                    if len(parts) >= 2:
                        results["http_method"] = parts[0]
                        results["http_path"] = parts[1]
                        
                    # Host başlığını çıkar
                    host_match = re.search(r'Host:\s+([^\r\n]+)', payload)
                    if host_match:
                        results["http_host"] = host_match.group(1)
                    
                    # User-Agent başlığını çıkar
                    ua_match = re.search(r'User-Agent:\s+([^\r\n]+)', payload)
                    if ua_match:
                        results["http_user_agent"] = ua_match.group(1)
                        
                elif payload.startswith("HTTP/"):
                    results["http_type"] = "Response"
                    
                    # Durum kodunu çıkar
                    first_line = payload.split("\r\n")[0]
                    parts = first_line.split(" ")
                    if len(parts) >= 2:
                        try:
                            results["http_status"] = int(parts[1])
                        except:
                            pass
                            
                    # İçerik tipini çıkar
                    content_type_match = re.search(r'Content-Type:\s+([^\r\n]+)', payload)
                    if content_type_match:
                        results["http_content_type"] = content_type_match.group(1)
            except:
                pass
                
        return results
        
    def _analyze_wifi(self, packet):
        """WiFi paketini analiz et"""
        results = {}
        
        # Management Frame (Type 0)
        if packet[Dot11].type == 0:
            
            # Beacon Frame (Subtype 8)
            if packet.haslayer(Dot11Beacon):
                # SSID çıkar
                if hasattr(packet[Dot11Beacon], 'info'):
                    try:
                        ssid = packet[Dot11Beacon].info.decode('utf-8')
                        results["wifi_ssid"] = ssid
                    except:
                        results["wifi_ssid"] = str(packet[Dot11Beacon].info)
                
                # Kanal numarası
                try:
                    channel = int(ord(packet[Dot11Elt:3].info))
                    results["wifi_channel"] = channel
                except:
                    pass
                    
                # Güvenlik bilgisi
                crypto = set()
                
                # Eski yöntem
                capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                if re.search("privacy", capability):
                    crypto.add("WEP")
                    
                # RSN IE
                if packet.haslayer(Dot11EltRSN):
                    crypto.add("WPA2")
                
                # MS WPA IE
                elif packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 221 and packet[Dot11Elt].info.startswith(b'\x00\x50\xf2\x01\x01\x00'):
                    crypto.add("WPA")
                
                if crypto:
                    results["wifi_crypto"] = list(crypto)
                else:
                    results["wifi_crypto"] = ["OPEN"]
                    
            # Probe Request (Subtype 4)
            elif packet.haslayer(Dot11ProbeReq):
                if hasattr(packet[Dot11ProbeReq], 'info'):
                    try:
                        ssid = packet[Dot11ProbeReq].info.decode('utf-8')
                        if ssid:
                            results["wifi_probe_ssid"] = ssid
                    except:
                        pass
                        
            # Authentication (Subtype 11)
            elif packet.haslayer(Dot11Auth):
                algo = packet[Dot11Auth].algo
                seqnum = packet[Dot11Auth].seqnum
                
                auth_algos = {0: "Open System", 1: "Shared Key"}
                results["wifi_auth_algo"] = auth_algos.get(algo, str(algo))
                results["wifi_auth_seq"] = seqnum
                
            # Association Request/Response (Subtype 0, 1)
            elif packet.haslayer(Dot11AssoReq):
                if hasattr(packet[Dot11AssoReq], 'info'):
                    try:
                        ssid = packet[Dot11AssoReq].info.decode('utf-8')
                        results["wifi_asso_ssid"] = ssid
                    except:
                        pass
                        
            # Deauthentication (Subtype 12)
            elif packet.haslayer(Dot11Deauth):
                reason = packet[Dot11Deauth].reason
                
                deauth_reasons = {
                    1: "Unspecified reason",
                    2: "Previous authentication no longer valid",
                    3: "Deauthenticated because sending STA is leaving",
                    4: "Disassociated due to inactivity",
                    5: "Disassociated because AP is unable to handle all currently associated STAs",
                    6: "Class 2 frame received from nonauthenticated STA",
                    7: "Class 3 frame received from nonassociated STA",
                    8: "Disassociated because sending STA is leaving BSS",
                    9: "STA requesting (re)association is not authenticated with responding STA"
                }
                
                results["wifi_deauth_reason"] = deauth_reasons.get(reason, str(reason))
                
        # WiFi Data Frame (Type 2)
        elif packet[Dot11].type == 2:
            # EAPOL paketi (WPA/WPA2 handshake)
            if packet.haslayer(EAPOL):
                results["wifi_eapol"] = True
                
                # Handshake mesaj numarası
                if packet.haslayer(EAPOL) and hasattr(packet[EAPOL], 'key_info'):
                    key_info = packet[EAPOL].key_info
                    
                    if key_info & 0x008:  # Key MIC set
                        if key_info & 0x100:  # Pairwise key bit
                            if not key_info & 0x040:  # Install bit NOT set
                                results["wifi_eapol_msg"] = 4
                            else:
                                results["wifi_eapol_msg"] = 3
                        else:
                            results["wifi_eapol_msg"] = 2
                    else:
                        results["wifi_eapol_msg"] = 1
                        
        return results

# ===== Filtreleme Modülü =====

class FilterManager:
    """Paket filtreleme yöneticisi"""
    
    def __init__(self, verbose=False):
        """Filtre yöneticisini başlat"""
        self.verbose = verbose
        self.active_filters = {}
        
    def create_filter_string(self, protocol=None, port=None, ip=None, net=None, 
                             mac=None, ssid=None, host=None, custom_filter=None):
        """BPF filtre formatında bir filtre oluştur"""
        filters = []
        
        # Temel protokol filtresi
        if protocol:
            proto_filter = " or ".join([p.lower() for p in protocol])
            filters.append(f"({proto_filter})")
        
        # Port filtresi
        if port:
            port_filter = " or ".join([f"port {p}" for p in port])
            filters.append(f"({port_filter})")
        
        # IP filtresi
        if ip:
            ip_filter = " or ".join([f"host {addr}" for addr in ip])
            filters.append(f"({ip_filter})")
        
        # Ağ filtresi
        if net:
            net_filters = []
            for net_addr in net:
                try:
                    network = ipaddress.IPv4Network(net_addr, strict=False)
                    net_filters.append(f"net {network.network_address} mask {network.netmask}")
                except:
                    if self.verbose:
                        UI.print_error(f"Geçersiz ağ adresi: {net_addr}, yoksayılıyor.")
            if net_filters:
                filters.append(f"({' or '.join(net_filters)})")
                
        # MAC adresi filtresi
        if mac:
            mac_filter = " or ".join([f"ether host {addr}" for addr in mac])
            filters.append(f"({mac_filter})")
            
        # Host filtresi (alan adı veya IP)
        if host:
            host_filter = " or ".join([f"host {h}" for h in host])
            filters.append(f"({host_filter})")
        
        # Özel filtre
        if custom_filter:
            filters.append(f"({custom_filter})")
        
        # WiFi SSID filtresi - SSID için özel işleme gerekir, BPF'ye doğrudan eklenemez
        # Bu filtre paket içeriğinde denetlenir
        if ssid:
            self.active_filters["ssid"] = ssid
            
        # Tüm filtreleri birleştir
        final_filter = " and ".join(filters) if filters else ""
        
        if self.verbose and final_filter:
            UI.print_info(f"Oluşturulan BPF filtresi: {final_filter}")
            
        return final_filter
    
    def apply_post_filters(self, packet, packet_info):
        """Paket yakalandıktan sonra uygulanan filtreler"""
        # Şu anda sadece SSID filtresi var
        if "ssid" in self.active_filters and "wifi_ssid" in packet_info:
            ssid_filters = self.active_filters["ssid"]
            wifi_ssid = packet_info["wifi_ssid"]
            
            # Her SSID filtresi için kontrol yap
            for ssid_filter in ssid_filters:
                # Tam eşleşme veya regex
                if ssid_filter == wifi_ssid or (ssid_filter.startswith("/") and ssid_filter.endswith("/") and re.search(ssid_filter[1:-1], wifi_ssid)):
                    return True
                    
            # Hiçbir SSID eşleşmedi
            return False
            
        # Filtre yoksa veya SSID içermeyen paketse geçir
        return True

# ===== Çıktı Modülü =====

class OutputManager:
    """Çıktı yönetimi sınıfı"""
    
    def __init__(self, quiet=False, verbose=False, output_format="text"):
        """Çıktı yöneticisini başlat"""
        self.quiet = quiet
        self.verbose = verbose
        self.output_format = output_format
        
    def print_packet(self, packet_info):
        """Paket bilgisini ekrana yazdır"""
        # Sessiz modda sadece önemli paketleri göster
        if self.quiet and not self._is_important_packet(packet_info):
            return
            
        # IP paketi için standart çıktı
        if "src_ip" in packet_info and "dst_ip" in packet_info:
            self._print_ip_packet(packet_info)
            
        # WiFi paketi için özel çıktı
        elif "wifi_type" in packet_info:
            self._print_wifi_packet(packet_info)
            
        # Diğer paket tipleri
        else:
            self._print_other_packet(packet_info)
            
        # Önemli tespit varsa daha detaylı göster
        if self._is_important_packet(packet_info):
            self._print_highlights(packet_info)
            
    def _print_ip_packet(self, p):
        """IP paketi çıktısı"""
        # Renk seçimi
        color = ""
        if p.get("is_http"):
            color = Colors.GREEN
        elif p.get("is_https"):
            color = Colors.BLUE
        elif p.get("protocol") == "DNS":
            color = Colors.CYAN
        elif p.get("protocol") == "ARP":
            color = Colors.YELLOW
            
        # Temel paket bilgisini yazdır
        print(f"{color}{p['timestamp']} | "
              f"{p['src_ip']}:{p.get('src_port', 'N/A')} -> "
              f"{p['dst_ip']}:{p.get('dst_port', 'N/A')} | "
              f"{p['protocol']}{' ' + p.get('service', '') if p.get('service') else ''} | "
              f"Boyut: {p['size']} byte{Colors.ENDC}")
              
        # TCP bayraklarını göster
        if p.get("tcp_flags"):
            print(f"  {Colors.BRIGHT_BLACK}TCP Flags: {', '.join(p['tcp_flags'])}{Colors.ENDC}")
              
        # HTTP detayları
        if p.get("http_type") == "Request":
            print(f"  {Colors.GREEN}HTTP {p.get('http_method', '')} {p.get('http_path', '')}{Colors.ENDC}")
            if p.get("http_host"):
                print(f"  {Colors.GREEN}Host: {p.get('http_host')}{Colors.ENDC}")
                
        elif p.get("http_type") == "Response":
            status = p.get("http_status", "")
            status_color = Colors.GREEN if status < 400 else Colors.RED
            print(f"  {status_color}HTTP Response: {status}{Colors.ENDC}")
            
            if p.get("http_content_type"):
                print(f"  {Colors.GREEN}Content-Type: {p.get('http_content_type')}{Colors.ENDC}")
                
        # DNS detayları
        if p.get("dns_type"):
            if p.get("dns_type") == "Query":
                print(f"  {Colors.CYAN}DNS Query: {p.get('dns_query', '')} ({p.get('dns_query_type', '')}){Colors.ENDC}")
            elif p.get("dns_type") == "Response":
                print(f"  {Colors.CYAN}DNS Response: {p.get('dns_query', '')}{Colors.ENDC}")
                
                if p.get("dns_answers"):
                    for answer in p["dns_answers"]:
                        print(f"    {Colors.CYAN}{answer['type']}: {answer['data']}{Colors.ENDC}")
    
    def _print_wifi_packet(self, p):
        """WiFi paketi çıktısı"""
        # Renk ve simge seçimi
        wifi_colors = {
            "Beacon": Colors.GREEN,
            "Probe Request": Colors.YELLOW,
            "Probe Response": Colors.BLUE,
            "Authentication": Colors.MAGENTA,
            "Association Request": Colors.CYAN,
            "Association Response": Colors.CYAN,
            "Deauthentication": Colors.RED,
            "Data": Colors.WHITE
        }
        
        color = wifi_colors.get(p.get("wifi_type", ""), Colors.WHITE)
        
        # MAC bilgileri
        src_mac = p.get("src_mac", "N/A")
        dst_mac = p.get("dst_mac", "N/A")
        
        # Temel paket bilgisi
        print(f"{color}{p['timestamp']} | "
              f"{src_mac} -> {dst_mac} | "
              f"WiFi {p.get('wifi_type', 'Unknown')} | "
              f"Boyut: {p['size']} byte{Colors.ENDC}")
        
        # SSID bilgisi
        if p.get("wifi_ssid"):
            print(f"  {color}SSID: {p['wifi_ssid']}{Colors.ENDC}")
            
            # Güvenlik bilgisi
            if p.get("wifi_crypto"):
                print(f"  {color}Güvenlik: {', '.join(p['wifi_crypto'])}{Colors.ENDC}")
                
            # Kanal bilgisi
            if p.get("wifi_channel"):
                print(f"  {color}Kanal: {p['wifi_channel']}{Colors.ENDC}")
                
        # Probe istekleri
        elif p.get("wifi_probe_ssid"):
            print(f"  {Colors.YELLOW}Aranan SSID: {p['wifi_probe_ssid']}{Colors.ENDC}")
            
        # Kimlik doğrulama
        elif p.get("wifi_auth_algo"):
            print(f"  {Colors.MAGENTA}Doğrulama: {p['wifi_auth_algo']} (Seq: {p.get('wifi_auth_seq', 'N/A')}){Colors.ENDC}")
            
        # WPA/WPA2 Handshake
        elif p.get("wifi_eapol"):
            print(f"  {Colors.BOLD}{Colors.RED}WPA Handshake! Mesaj {p.get('wifi_eapol_msg', 'N/A')}{Colors.ENDC}")
            
        # Deauth sebebi
        elif p.get("wifi_deauth_reason"):
            print(f"  {Colors.RED}Deauth Sebebi: {p['wifi_deauth_reason']}{Colors.ENDC}")
            
    def _print_other_packet(self, p):
        """Diğer paket tipleri için çıktı"""
        proto = p.get("protocol", "UNKNOWN")
        
        # Temel bilgileri göster
        print(f"{Colors.WHITE}{p['timestamp']} | "
              f"Protokol: {proto} | "
              f"Boyut: {p['size']} byte{Colors.ENDC}")
        
        # İçerik tipi bilgisi
        if p.get("content_type"):
            print(f"  {Colors.YELLOW}İçerik: {p['content_type']}{Colors.ENDC}")
    
    def _print_highlights(self, p):
        """Önemli tespitleri vurgula"""
        # Anahtar kelime eşleşmeleri
        if p.get("keyword_matches"):
            print(f"\n{Colors.BOLD}{Colors.RED}[!] ANAHTAR KELİME EŞLEŞME:{Colors.ENDC}")
            for match in p["keyword_matches"]:
                print(f"  {Colors.RED}Kelime: {match['keyword']}{Colors.ENDC}")
                print(f"  {Colors.RED}Bağlam: {match['context']}{Colors.ENDC}\n")
                
        # Regex eşleşmeleri
        if p.get("regex_matches"):
            print(f"\n{Colors.BOLD}{Colors.RED}[!] HASSAS VERİ TESPİTİ:{Colors.ENDC}")
            for match in p["regex_matches"]:
                print(f"  {Colors.RED}Desen: {match['pattern'][:30]}...{Colors.ENDC}")
                print(f"  {Colors.RED}Değer: {match['value']}{Colors.ENDC}")
                if 'context' in match:
                    print(f"  {Colors.RED}Bağlam: {match['context']}{Colors.ENDC}\n")
                    
        # Kimlik doğrulama verileri
        if p.get("auth_data"):
            print(f"\n{Colors.BOLD}{Colors.RED}[!] KİMLİK DOĞRULAMA VERİSİ TESPİT EDİLDİ:{Colors.ENDC}")
            for auth in p["auth_data"]:
                print(f"  {Colors.RED}Tür: {auth['type']}{Colors.ENDC}")
                if 'username' in auth:
                    print(f"  {Colors.RED}Kullanıcı: {auth['username']}{Colors.ENDC}")
                if 'password' in auth:
                    print(f"  {Colors.RED}Şifre: {auth['password']}{Colors.ENDC}")
                if 'token' in auth:
                    print(f"  {Colors.RED}Token: {auth['token']}{Colors.ENDC}")
                print()
                
        # HTTP POST form verileri
        if p.get("http_post_data"):
            post_data = p["http_post_data"]
            print(f"\n{Colors.BOLD}{Colors.YELLOW}[!] HTTP FORM VERİSİ:{Colors.ENDC}")
            print(f"  {Colors.YELLOW}Format: {post_data['format']}{Colors.ENDC}")
            
            # JSON veya URL kodlanmış verileri göster
            if post_data['format'] == 'json':
                for key, value in post_data['data'].items():
                    print(f"  {Colors.YELLOW}{key}: {value}{Colors.ENDC}")
            else:
                for key, value in post_data['data'].items():
                    print(f"  {Colors.YELLOW}{key}: {value}{Colors.ENDC}")
                    
        # TLS tespit
        if p.get("tls_detected"):
            print(f"\n{Colors.BOLD}{Colors.BLUE}[!] TLS TRAFİK TESPİTİ:{Colors.ENDC}")
            if p.get("tls_type"):
                print(f"  {Colors.BLUE}TLS Mesaj: {p['tls_type']}{Colors.ENDC}")
                
        # Binary eşleşmeler
        if p.get("binary_matches"):
            print(f"\n{Colors.BOLD}{Colors.MAGENTA}[!] BINARY VERİDE HASSAS VERİ TESPİTİ:{Colors.ENDC}")
            for match in p["binary_matches"]:
                print(f"  {Colors.MAGENTA}Desen: {match['pattern'][:30]}...{Colors.ENDC}")
                print(f"  {Colors.MAGENTA}Değer: {match['value']}{Colors.ENDC}\n")
                
        # EAPOL (WPA/WPA2 Handshake)
        if p.get("wifi_eapol"):
            print(f"\n{Colors.BOLD}{Colors.RED}[!] WPA/WPA2 HANDSHAKE TESPİTİ - MESAJ {p.get('wifi_eapol_msg', 'N/A')}{Colors.ENDC}")
            print(f"  {Colors.RED}BSSID: {p.get('bssid', 'N/A')}{Colors.ENDC}")
            print(f"  {Colors.RED}İstemci MAC: {p.get('src_mac', 'N/A')}{Colors.ENDC}\n")
                
        # Ayırıcı çizgi ekle
        if self._is_important_packet(p):
            print("-" * 80)
            
    def _is_important_packet(self, packet_info):
        """Önemli bir paket mi kontrol et"""
        return (
            packet_info.get("keyword_matches") or 
            packet_info.get("regex_matches") or 
            packet_info.get("auth_data") or 
            packet_info.get("http_post_data") or
            packet_info.get("binary_matches") or
            packet_info.get("wifi_eapol")
        )
    
    def print_statistics(self, stats, start_time):
            """İstatistikleri göster"""
            duration = (datetime.datetime.now() - start_time).total_seconds()
            
            UI.print_section("YAKALAMA İSTATİSTİKLERİ")
            
            print(f"{Colors.BOLD}Genel İstatistikler:{Colors.ENDC}")
            print(f"Toplam Süre: {duration:.2f} saniye")
            print(f"Toplam Paket: {stats['total_packets']}")
            
            # Saniyedeki paket sayısı
            if duration > 0:
                pps = stats['total_packets'] / duration
                print(f"Paket/Saniye: {pps:.2f}")
            
            # Protokol dağılımı
            if stats.get("protocol_stats"):
                print(f"\n{Colors.BOLD}Protokol Dağılımı:{Colors.ENDC}")
                for proto, count in sorted(stats["protocol_stats"].items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / stats["total_packets"]) * 100 if stats["total_packets"] > 0 else 0
                    print(f"  {proto}: {count} paket ({percentage:.1f}%)")
            
            # HTTP/HTTPS istatistikleri
            if stats.get("http_packets") or stats.get("https_packets"):
                print(f"\n{Colors.BOLD}Web Trafiği:{Colors.ENDC}")
                print(f"  HTTP Paketleri: {stats.get('http_packets', 0)}")
                print(f"  HTTPS Paketleri: {stats.get('https_packets', 0)}")
                if stats.get("http_methods"):
                    print("  HTTP Metodları:")
                    for method, count in sorted(stats["http_methods"].items(), key=lambda x: x[1], reverse=True):
                        print(f"    {method}: {count}")
            
            # WiFi istatistikleri
            if stats.get("wifi_stats"):
                print(f"\n{Colors.BOLD}WiFi İstatistikleri:{Colors.ENDC}")
                print(f"  Beacon Paketleri: {stats['wifi_stats'].get('beacon', 0)}")
                print(f"  Probe İstekleri: {stats['wifi_stats'].get('probe_req', 0)}")
                print(f"  Kimlik Doğrulama: {stats['wifi_stats'].get('auth', 0)}")
                print(f"  Deauth Paketleri: {stats['wifi_stats'].get('deauth', 0)}")
                print(f"  WPA Handshake: {stats['wifi_stats'].get('eapol', 0)}")
                
                # Tespit edilen SSID'ler
                if stats.get("ssid_list"):
                    print(f"\n{Colors.BOLD}Tespit Edilen SSID'ler:{Colors.ENDC}")
                    for ssid, info in sorted(stats["ssid_list"].items()):
                        crypto = ", ".join(info.get("crypto", ["UNKNOWN"]))
                        channel = info.get("channel", "?")
                        print(f"  {ssid} (Kanal: {channel}, Güvenlik: {crypto})")
            
            # En aktif IP'ler
            if stats.get("ip_stats"):
                print(f"\n{Colors.BOLD}En Aktif 10 IP Adresi:{Colors.ENDC}")
                for ip, count in sorted(stats["ip_stats"].items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  {ip}: {count} paket")
            
            # En aktif portlar
            if stats.get("port_stats"):
                print(f"\n{Colors.BOLD}En Aktif 10 Port:{Colors.ENDC}")
                for port, count in sorted(stats["port_stats"].items(), key=lambda x: x[1], reverse=True)[:10]:
                    if isinstance(port, int):
                        service = self._get_service_name(port)
                        if service:
                            print(f"  {port} ({service}): {count} paket")
                        else:
                            print(f"  {port}: {count} paket")
                    else:
                        print(f"  {port}: {count} paket")
            
            # Anahtar kelime ve hassas veri tespitleri
            if stats.get("keyword_stats") or stats.get("sensitive_data_stats"):
                print(f"\n{Colors.BOLD}Tespit İstatistikleri:{Colors.ENDC}")
                
                if stats.get("keyword_stats"):
                    print("  Anahtar Kelime Eşleşmeleri:")
                    for keyword, count in sorted(stats["keyword_stats"].items(), key=lambda x: x[1], reverse=True):
                        print(f"    {keyword}: {count} eşleşme")
                        
                if stats.get("sensitive_data_stats"):
                    print("  Hassas Veri Tespitleri:")
                    for pattern, count in sorted(stats["sensitive_data_stats"].items(), key=lambda x: x[1], reverse=True):
                        pattern_name = pattern[:30] + "..." if len(pattern) > 30 else pattern
                        print(f"    {pattern_name}: {count} eşleşme")
            
            # Paket boyutu istatistikleri
            if stats.get("packet_sizes"):
                sizes = stats["packet_sizes"]
                avg_size = sum(sizes) / len(sizes) if sizes else 0
                min_size = min(sizes) if sizes else 0
                max_size = max(sizes) if sizes else 0
                
                print(f"\n{Colors.BOLD}Paket Boyutu İstatistikleri:{Colors.ENDC}")
                print(f"  Ortalama: {avg_size:.1f} byte")
                print(f"  Minimum: {min_size} byte")
                print(f"  Maksimum: {max_size} byte")
            
            print("\n" + "=" * 80)
    
    def _get_service_name(self, port):
        """Yaygın port numarasına göre servis adını döndür"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
            67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 
            123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 
            143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS", 
            445: "SMB", 465: "SMTPS", 514: "Syslog", 636: "LDAPS", 993: "IMAPS", 
            995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 
            5901: "VNC", 5985: "WinRM", 8000: "HTTP-Alt", 8008: "HTTP", 
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        
        return common_ports.get(port, "")
        
    def save_to_file(self, output_file, data):
        """Yakalanan verileri dosyaya kaydet"""
        # Dosya formatını belirle
        file_format = os.path.splitext(output_file)[1].lower()
        
        try:
            # JSON formatı
            if file_format == '.json':
                self._save_json(output_file, data)
                
            # PCAP formatı
            elif file_format == '.pcap' or file_format == '.cap':
                self._save_pcap(output_file, data)
                
            # Metin formatı varsayılan
            else:
                self._save_text(output_file, data)
                
            UI.print_success(f"Veriler {output_file} dosyasına kaydedildi.")
            
        except Exception as e:
            UI.print_error(f"Dosya kaydı sırasında hata: {str(e)}")
    
    def _save_json(self, file_path, data):
        """JSON formatında kaydet"""
        # Ham paket nesnesini ve diğer serileştirilemeyecek verileri temizle
        clean_data = self._clean_data_for_serialization(data)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(clean_data, f, indent=2, default=str)
    
    def _save_pcap(self, file_path, data):
        """PCAP formatında kaydet"""
        # Sadece ham paketleri içeren bir liste oluştur
        packets = []
        for packet_info in data.get("packets", []):
            if "raw_packet" in packet_info:
                packets.append(packet_info["raw_packet"])
                
        # Paketleri PCAP dosyasına yaz
        if packets:
            wrpcap(file_path, packets)
        else:
            raise ValueError("Kaydedilecek paket bulunamadı")
    
    def _save_text(self, file_path, data):
        """Metin formatında kaydet"""
        with open(file_path, 'w', encoding='utf-8') as f:
            # Başlık
            f.write("=" * 80 + "\n")
            f.write("PACKETMASTER YAKALAMA RAPORU\n")
            f.write("=" * 80 + "\n")
            f.write(f"Tarih: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            # Genel istatistikler
            stats = data.get("stats", {})
            f.write(f"Toplam Paket: {stats.get('total_packets', 0)}\n")
            f.write(f"HTTP Paketleri: {stats.get('http_packets', 0)}\n")
            f.write(f"HTTPS Paketleri: {stats.get('https_packets', 0)}\n\n")
            
            # Anahtar kelime eşleşmeleri
            keyword_matches = data.get("keyword_matches", [])
            if keyword_matches:
                f.write("-" * 80 + "\n")
                f.write("ANAHTAR KELİME EŞLEŞMELERİ\n")
                f.write("-" * 80 + "\n")
                
                for match in keyword_matches:
                    f.write(f"Zaman: {match.get('timestamp', 'N/A')}\n")
                    f.write(f"Anahtar Kelime: {match.get('keyword', 'N/A')}\n")
                    if 'src_ip' in match and 'dst_ip' in match:
                        f.write(f"Bağlantı: {match.get('src_ip', 'N/A')}:{match.get('src_port', 'N/A')} -> ")
                        f.write(f"{match.get('dst_ip', 'N/A')}:{match.get('dst_port', 'N/A')}")
                    f.write(f" ({match.get('protocol', 'N/A')})\n")
                    f.write(f"Bağlam: {match.get('context', 'N/A')}\n\n")
            
            # Hassas veri eşleşmeleri
            sensitive_matches = []
            for packet_info in data.get("packets", []):
                if packet_info.get("regex_matches"):
                    for match in packet_info["regex_matches"]:
                        match["timestamp"] = packet_info.get("timestamp", "N/A")
                        if 'src_ip' in packet_info:
                            match["src_ip"] = packet_info["src_ip"]
                            match["dst_ip"] = packet_info["dst_ip"]
                            match["src_port"] = packet_info.get("src_port", "N/A")
                            match["dst_port"] = packet_info.get("dst_port", "N/A")
                            match["protocol"] = packet_info.get("protocol", "N/A")
                        sensitive_matches.append(match)
                        
            if sensitive_matches:
                f.write("-" * 80 + "\n")
                f.write("HASSAS VERİ TESPİTLERİ\n")
                f.write("-" * 80 + "\n")
                
                for match in sensitive_matches:
                    f.write(f"Zaman: {match.get('timestamp', 'N/A')}\n")
                    f.write(f"Desen: {match.get('pattern', 'N/A')}\n")
                    f.write(f"Değer: {match.get('value', 'N/A')}\n")
                    if 'src_ip' in match:
                        f.write(f"Bağlantı: {match.get('src_ip', 'N/A')}:{match.get('src_port', 'N/A')} -> ")
                        f.write(f"{match.get('dst_ip', 'N/A')}:{match.get('dst_port', 'N/A')}")
                        f.write(f" ({match.get('protocol', 'N/A')})\n")
                    f.write(f"Bağlam: {match.get('context', 'N/A')}\n\n")
            
            # Paket günlüğü
            f.write("-" * 80 + "\n")
            f.write("PAKET GÜNLÜĞÜ\n")
            f.write("-" * 80 + "\n")
            
            for packet in data.get("packets", []):
                # Temel paket bilgisi
                if 'src_ip' in packet and 'dst_ip' in packet:
                    f.write(f"{packet.get('timestamp', 'N/A')} | {packet.get('src_ip', 'N/A')}:")
                    f.write(f"{packet.get('src_port', 'N/A')} -> {packet.get('dst_ip', 'N/A')}:")
                    f.write(f"{packet.get('dst_port', 'N/A')} | {packet.get('protocol', 'N/A')}")
                    
                    if packet.get('service'):
                        f.write(f" {packet['service']}")
                        
                    f.write(f" | Boyut: {packet.get('size', 0)} byte")
                    
                # WiFi paketi
                elif 'wifi_type' in packet:
                    f.write(f"{packet.get('timestamp', 'N/A')} | {packet.get('src_mac', 'N/A')} -> ")
                    f.write(f"{packet.get('dst_mac', 'N/A')} | WiFi {packet.get('wifi_type', 'Unknown')}")
                    
                    if packet.get('wifi_ssid'):
                        f.write(f" | SSID: {packet['wifi_ssid']}")
                        
                    f.write(f" | Boyut: {packet.get('size', 0)} byte")
                    
                # Anahtar kelime ve hassas veri işaretleri
                if packet.get('keyword_matches'):
                    keywords = [m['keyword'] for m in packet['keyword_matches']]
                    f.write(f" | Anahtar Kelimeler: {', '.join(keywords)}")
                    
                if packet.get('regex_matches'):
                    f.write(f" | [!] HASSAS VERİ")
                    
                if packet.get('auth_data'):
                    f.write(f" | [!] KİMLİK BİLGİSİ")
                    
                f.write("\n")
    
    def _clean_data_for_serialization(self, data):
        """Veriyi JSON serileştirme için temizle"""
        # Derin kopya oluştur
        import copy
        clean_data = copy.deepcopy(data)
        
        # Paketlerdeki serileştirilemeyen öğeleri kaldır
        if "packets" in clean_data:
            for packet in clean_data["packets"]:
                if "raw_packet" in packet:
                    del packet["raw_packet"]
                
                # Diğer serileştirilemeyen alanları kaldır
                for key in list(packet.keys()):
                    if isinstance(packet[key], (set, bytes, bytearray)):
                        packet[key] = str(packet[key])
                    elif hasattr(packet[key], '__dict__'):
                        packet[key] = str(packet[key])
        
        return clean_data

# ===== Ana Sınıf =====

class PacketMaster:
    """Ana PacketMaster sınıfı"""
    
    def __init__(self, args=None):
        """PacketMaster'ı başlat"""
        self.args = args or {}
        self.running = False
        self.start_time = None
        
        # Verbose modu
        self.verbose = args.verbose if hasattr(args, 'verbose') else False
        
        # Başlık banner'ını göster
        if not hasattr(args, 'no_banner') or not args.no_banner:
            UI.print_banner()
        
        # Alt sistemleri başlat
        self.analyzer = PacketAnalyzer(
            keywords=args.keyword if hasattr(args, 'keyword') else None,
            regex_patterns=args.regex if hasattr(args, 'regex') else None,
            sensitive_info=not args.no_sensitive if hasattr(args, 'no_sensitive') else True,
            verbose=self.verbose
        )
        
        self.filter_manager = FilterManager(verbose=self.verbose)
        
        self.output_manager = OutputManager(
            quiet=args.quiet if hasattr(args, 'quiet') else False,
            verbose=self.verbose,
            output_format=args.format if hasattr(args, 'format') else "text"
        )
        
        # Veri yapıları
        self.captured_packets = []
        self.keyword_matches = []
        self.regex_matches = []
        self.lock = threading.Lock()
        
        # İstatistikler
        self.stats = {
            "total_packets": 0,
            "http_packets": 0,
            "https_packets": 0,
            "ip_stats": defaultdict(int),
            "port_stats": defaultdict(int),
            "protocol_stats": defaultdict(int),
            "keyword_stats": defaultdict(int),
            "sensitive_data_stats": defaultdict(int),
            "wifi_stats": defaultdict(int),
            "http_methods": defaultdict(int),
            "packet_sizes": [],
            "ssid_list": {}  # key: SSID, value: {"bssid": X, "channel": Y, "crypto": [...]}
        }
        
        # Ctrl+C işleyicisi
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def start(self):
        """Yakalamayı başlat"""
        if self.running:
            UI.print_warning("Yakalama zaten çalışıyor!")
            return
            
        self.running = True
        self.start_time = datetime.datetime.now()
        
        # Ağ arayüzünü belirle 
        interface = self.args.interface if hasattr(self.args, 'interface') else None
        
        # Filtre oluştur
        capture_filter = self.filter_manager.create_filter_string(
            protocol=self.args.protocol if hasattr(self.args, 'protocol') else None,
            port=self.args.port if hasattr(self.args, 'port') else None,
            ip=self.args.ip if hasattr(self.args, 'ip') else None,
            net=self.args.net if hasattr(self.args, 'net') else None,
            mac=self.args.mac if hasattr(self.args, 'mac') else None,
            ssid=self.args.ssid if hasattr(self.args, 'ssid') else None,
            host=self.args.host if hasattr(self.args, 'host') else None,
            custom_filter=self.args.filter if hasattr(self.args, 'filter') else None
        )
        
        # WiFi monitör modunu kontrol et
        if hasattr(self.args, 'monitor') and self.args.monitor:
            UI.print_info("WiFi monitör modu etkinleştiriliyor...")
            # Monitor mod etkinleştir ve arayüzü belirle
            try:
                if not interface:
                    wireless_interfaces = self._get_wireless_interfaces()
                    if wireless_interfaces:
                        interface = wireless_interfaces[0]
                        UI.print_info(f"Otomatik olarak kablosuz arayüz seçildi: {interface}")
                    else:
                        UI.print_error("Kablosuz arayüz bulunamadı")
                        return
                
                # Monitör modu etkinleştir
                self._enable_monitor_mode(interface)
                
            except Exception as e:
                UI.print_error(f"Monitör modu etkinleştirme hatası: {str(e)}")
                return
        
        # Program bilgilerini göster
        UI.print_section("YAKALAMA AYARLARI")
        print(f"Arayüz: {interface or 'Varsayılan'}")
        print(f"Filtre: {capture_filter or 'Yok'}")
        if hasattr(self.args, 'keyword') and self.args.keyword:
            print(f"Anahtar Kelimeler: {', '.join(self.args.keyword)}")
        if hasattr(self.args, 'regex') and self.args.regex:
            print(f"Regex Desenleri: {', '.join(self.args.regex)}")
        if hasattr(self.args, 'output') and self.args.output:
            print(f"Çıktı Dosyası: {self.args.output}")
        if hasattr(self.args, 'monitor') and self.args.monitor:
            print(f"WiFi Monitör Modu: Aktif")
        print("=" * 80)
        print("Başlatılıyor...")
        print(f"{Colors.BOLD}Çıkmak için Ctrl+C'ye basın{Colors.ENDC}")
        print("-" * 80)
        
        # İstatistik iş parçacığı
        if hasattr(self.args, 'stats') and self.args.stats:
            stats_thread = threading.Thread(target=self._show_stats_periodically, daemon=True)
            stats_thread.start()
        
        try:
            # Paket yakalamayı başlat
            sniff(
                iface=interface, 
                filter=capture_filter, 
                prn=self._packet_callback, 
                count=self.args.count if hasattr(self.args, 'count') else 0,
                store=0  # Performans için paketleri saklama
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            UI.print_error(f"Yakalama hatası: {str(e)}")
        finally:
            self.stop()
    
    def stop(self):
        """Yakalamayı durdur"""
        if not self.running:
            return
            
        self.running = False
        UI.print_info("Yakalama durduruldu.")
        
        # Monitör modundan çık
        if hasattr(self.args, 'monitor') and self.args.monitor and hasattr(self.args, 'interface'):
            self._disable_monitor_mode(self.args.interface)
        
        # İstatistikleri göster
        self.output_manager.print_statistics(self.stats, self.start_time)
        
        # Sonuçları kaydet
        if hasattr(self.args, 'output') and self.args.output:
            data = {
                "stats": self.stats,
                "packets": self.captured_packets,
                "keyword_matches": self.keyword_matches,
                "regex_matches": self.regex_matches
            }
            self.output_manager.save_to_file(self.args.output, data)

    def _packet_callback(self, packet):
        """Paket yakalama geri çağırma fonksiyonu"""
        try:
            # Paketi analiz et
            packet_info = self.analyzer.process_packet(packet)
            
            # Post filtrelerini uygula (BPF ile ifade edilemeyen filtreler)
            if not self.filter_manager.apply_post_filters(packet, packet_info):
                return
            
            # İstatistikleri güncelle
            with self.lock:
                self.stats["total_packets"] += 1
                
                # IP istatistikleri
                if 'src_ip' in packet_info:
                    self.stats["ip_stats"][packet_info["src_ip"]] += 1
                if 'dst_ip' in packet_info:
                    self.stats["ip_stats"][packet_info["dst_ip"]] += 1
                
                # Port istatistikleri
                if 'src_port' in packet_info and packet_info["src_port"] != "N/A":
                    self.stats["port_stats"][packet_info["src_port"]] += 1
                if 'dst_port' in packet_info and packet_info["dst_port"] != "N/A":
                    self.stats["port_stats"][packet_info["dst_port"]] += 1
                
                # Protokol istatistikleri
                if 'protocol' in packet_info:
                    self.stats["protocol_stats"][packet_info["protocol"]] += 1
                
                # Paket boyutu
                if 'size' in packet_info:
                    self.stats["packet_sizes"].append(packet_info["size"])
                
                # HTTP/HTTPS istatistikleri
                if packet_info.get("is_http"):
                    self.stats["http_packets"] += 1
                    if packet_info.get("http_method"):
                        self.stats["http_methods"][packet_info["http_method"]] += 1
                if packet_info.get("is_https"):
                    self.stats["https_packets"] += 1
                
                # WiFi istatistikleri
                if 'wifi_type' in packet_info:
                    wifi_type = packet_info["wifi_type"].lower()
                    if 'beacon' in wifi_type:
                        self.stats["wifi_stats"]["beacon"] += 1
                    elif 'probe request' in wifi_type:
                        self.stats["wifi_stats"]["probe_req"] += 1
                    elif 'authentication' in wifi_type:
                        self.stats["wifi_stats"]["auth"] += 1
                    elif 'deauthentication' in wifi_type:
                        self.stats["wifi_stats"]["deauth"] += 1
                    
                    # SSID bilgisi
                    if packet_info.get("wifi_ssid") and packet_info.get("bssid"):
                        ssid = packet_info["wifi_ssid"]
                        bssid = packet_info["bssid"]
                        
                        if ssid not in self.stats["ssid_list"]:
                            self.stats["ssid_list"][ssid] = {
                                "bssid": bssid,
                                "first_seen": datetime.datetime.now(),
                                "count": 0
                            }
                            
                            # Kanal ve güvenlik bilgisi
                            if packet_info.get("wifi_channel"):
                                self.stats["ssid_list"][ssid]["channel"] = packet_info["wifi_channel"]
                            if packet_info.get("wifi_crypto"):
                                self.stats["ssid_list"][ssid]["crypto"] = packet_info["wifi_crypto"]
                        
                        self.stats["ssid_list"][ssid]["count"] += 1
                        self.stats["ssid_list"][ssid]["last_seen"] = datetime.datetime.now()
                
                # EAPOL (WPA Handshake) istatistikleri
                if packet_info.get("wifi_eapol"):
                    self.stats["wifi_stats"]["eapol"] += 1
                
                # Anahtar kelime eşleşmeleri
                if packet_info.get("keyword_matches"):
                    for match in packet_info["keyword_matches"]:
                        keyword = match["keyword"]
                        self.stats["keyword_stats"][keyword] += 1
                        
                        # Daha sonra referans için kaydet
                        match_with_context = match.copy()
                        match_with_context.update({
                            "timestamp": packet_info["timestamp"],
                            "src_ip": packet_info.get("src_ip", "N/A"),
                            "dst_ip": packet_info.get("dst_ip", "N/A"),
                            "src_port": packet_info.get("src_port", "N/A"),
                            "dst_port": packet_info.get("dst_port", "N/A"),
                            "protocol": packet_info.get("protocol", "N/A")
                        })
                        self.keyword_matches.append(match_with_context)
                
                # Regex/hassas veri eşleşmeleri
                if packet_info.get("regex_matches"):
                    for match in packet_info["regex_matches"]:
                        pattern = match["pattern"]
                        self.stats["sensitive_data_stats"][pattern] += 1
                        
                        # Daha sonra referans için kaydet
                        match_with_context = match.copy()
                        match_with_context.update({
                            "timestamp": packet_info["timestamp"],
                            "src_ip": packet_info.get("src_ip", "N/A"),
                            "dst_ip": packet_info.get("dst_ip", "N/A"),
                            "src_port": packet_info.get("src_port", "N/A"),
                            "dst_port": packet_info.get("dst_port", "N/A"),
                            "protocol": packet_info.get("protocol", "N/A")
                        })
                        self.regex_matches.append(match_with_context)
                
                # Paketi sakla
                self.captured_packets.append(packet_info)
            
            # Paketi yazdır
            self.output_manager.print_packet(packet_info)
            
        except Exception as e:
            if self.verbose:
                UI.print_error(f"Paket işleme hatası: {str(e)}")
    
    def _signal_handler(self, sig, frame):
        """Ctrl+C işleyicisi"""
        UI.print_warning("\nProgram sonlandırılıyor, istatistikler hazırlanıyor...")
        self.stop()
        sys.exit(0)
    
    def _show_stats_periodically(self):
        """Periyodik olarak istatistikleri göster"""
        interval = self.args.stats_interval if hasattr(self.args, 'stats_interval') else 10  # varsayılan 10 saniye
        
        while self.running:
            time.sleep(interval)
            with self.lock:
                if self.stats["total_packets"] > 0:  # Sadece paket varsa göster
                    self.output_manager.print_statistics(self.stats, self.start_time)
    
    def _get_wireless_interfaces(self):
        """Sistemdeki kablosuz arayüzleri bul"""
        wireless_interfaces = []
        
        try:
            # Linux'ta kablosuz arayüzleri bul
            if os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    if os.path.exists(f'/sys/class/net/{iface}/wireless') or iface.startswith('wlan') or iface.startswith('mon'):
                        wireless_interfaces.append(iface)
            
            # Windows için (daha karmaşık)
            elif os.name == 'nt':
                # Windows'ta Python ile kablosuz arayüz bulmak zor
                # Genellikle özel kütüphaneler veya komut satırı araçları kullanılır
                try:
                    # ipconfig çıktısından kablosuz arayüzleri bulmaya çalış
                    import re
                    output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
                    # Kablosuz adaptör isimlerini ara
                    matches = re.finditer(r"(Wireless LAN|Kablosuz LAN).*?:\s*(.*?)\r?\n", output)
                    for match in matches:
                        wireless_interfaces.append(match.group(2).strip())
                except:
                    pass
            
            # macOS için
            elif sys.platform == 'darwin':
                try:
                    # networksetup -listallhardwareports çıktısını kullan
                    output = subprocess.check_output(["networksetup", "-listallhardwareports"]).decode('utf-8')
                    # Wi-Fi arayüzlerini bul
                    wifi_sections = re.finditer(r"Hardware Port: (Wi-Fi|AirPort).*?Device: (.*?)\n", output, re.DOTALL)
                    for match in wifi_sections:
                        wireless_interfaces.append(match.group(2).strip())
                except:
                    pass
                    
            if self.verbose:
                UI.print_info(f"Tespit edilen kablosuz arayüzler: {', '.join(wireless_interfaces)}")
                
        except Exception as e:
            if self.verbose:
                UI.print_error(f"Kablosuz arayüzleri bulma hatası: {str(e)}")
                
        return wireless_interfaces
    
    def _enable_monitor_mode(self, interface):
        """Kablosuz arayüzü monitör moduna al"""
        if not interface:
            return False
            
        try:
            # Linux için farklı yaklaşımlar
            if os.name == 'posix':
                # Önce NetworkManager gibi servisleri durdur
                try:
                    UI.print_info("Ağ servislerini durduruluyor...")
                    subprocess.run(["sudo", "airmon-ng", "check", "kill"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except:
                    pass
                
                # Arayüzü monitör moduna al
                # 1. airmon-ng kullanarak
                try:
                    UI.print_info(f"{interface} arayüzü monitör moduna alınıyor (airmon-ng)...")
                    result = subprocess.run(["sudo", "airmon-ng", "start", interface], 
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Yeni arayüz adını çıktıdan ayıkla
                    output = result.stdout.decode('utf-8')
                    match = re.search(r"(monitor mode enabled on|monitor mode vif created|monitor mode enabled for).*?(mon\d+|mon)", output)
                    if match:
                        monitor_iface = match.group(2).strip()
                        UI.print_success(f"Monitör modu etkinleştirildi: {monitor_iface}")
                        return monitor_iface
                except:
                    # 2. iw kullanarak
                    try:
                        UI.print_info(f"{interface} arayüzü monitör moduna alınıyor (iw)...")
                        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        subprocess.run(["sudo", "iw", interface, "set", "monitor", "none"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        
                        UI.print_success(f"Monitör modu etkinleştirildi: {interface}")
                        return interface
                    except:
                        pass
                        
                # 3. iwconfig kullanarak (eski sistemler için)
                try:
                    UI.print_info(f"{interface} arayüzü monitör moduna alınıyor (iwconfig)...")
                    subprocess.run(["sudo", "ifconfig", interface, "down"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iwconfig", interface, "mode", "monitor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "ifconfig", interface, "up"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    UI.print_success(f"Monitör modu etkinleştirildi: {interface}")
                    return interface
                except:
                    pass
            
            # macOS için (Macos'ta monitör modu airportd ile yapılır)
            elif sys.platform == 'darwin':
                UI.print_info(f"{interface} arayüzü monitör moduna alınıyor (macOS)...")
                
                # Airport yardımcı programını bul
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if os.path.exists(airport_path):
                    try:
                        subprocess.run(["sudo", airport_path, interface, "sniff"], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        UI.print_success(f"Monitör modu etkinleştirildi: {interface}")
                        return interface
                    except:
                        pass
                else:
                    UI.print_error("MacOS'ta airport aracı bulunamadı")
            
            # Windows için işlemler karmaşık ve genellikle üçüncü parti yazılım gerektirir
            elif os.name == 'nt':
                UI.print_warning("Windows'ta monitör modu etkinleştirmek için Npcap, Airpcap veya özel sürücüler gerekir.")
                UI.print_warning("Lütfen Scapy'nin Windows'ta monitör modunu desteklediğinden emin olun.")
                return interface
                
            UI.print_error(f"Monitör modu etkinleştirilemedi: {interface}")
            return False
                
        except Exception as e:
            UI.print_error(f"Monitör modu hatası: {str(e)}")
            return False
    
    def _disable_monitor_mode(self, interface):
        """Monitör modundan çık"""
        if not interface:
            return
            
        try:
            # Linux için
            if os.name == 'posix':
                try:
                    # airmon-ng ile
                    if interface.startswith('mon'):
                        subprocess.run(["sudo", "airmon-ng", "stop", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    else:
                        # Orijinal arayüzü bulmaya çalış
                        # Genellikle mon0 -> wlan0 gibi
                        original_iface = interface.replace('mon', 'wlan')
                        subprocess.run(["sudo", "airmon-ng", "stop", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        
                    UI.print_info(f"Monitör modu devre dışı bırakıldı: {interface}")
                except:
                    # iw ile
                    try:
                        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        subprocess.run(["sudo", "iw", interface, "set", "type", "managed"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        
                        UI.print_info(f"Monitör modu devre dışı bırakıldı: {interface}")
                    except:
                        pass
            
            # macOS için
            elif sys.platform == 'darwin':
                # macOS'ta monitör modunu kapatmak için Ctrl+C yeterlidir
                # Sniffing işlemi zaten durdurulmuş olur
                UI.print_info(f"MacOS monitör modu devre dışı bırakıldı")
                
        except Exception as e:
            UI.print_error(f"Monitör modu devre dışı bırakma hatası: {str(e)}")

# ===== Komut Satırı Arayüzü =====

def parse_arguments():
    """Komut satırı argümanlarını ayrıştır"""
    parser = argparse.ArgumentParser(
        description='PacketMaster - Gelişmiş Ağ Paket Yakalama ve Analiz Aracı',
        epilog='Örnek: sudo python3 packetmaster.py -i wlan0 -p 80 443 -k password email'
    )
    
    # Temel seçenekler
    parser.add_argument('-i', '--interface', 
                        help='Ağ arayüzü (örn. eth0, wlan0)')
    parser.add_argument('-c', '--count', type=int, default=0, 
                        help='Yakalanacak paket sayısı (0=sınırsız)')
    parser.add_argument('-o', '--output', 
                        help='Çıktı dosyası (örn. capture.txt, capture.json, capture.pcap)')
    parser.add_argument('-f', '--filter', 
                        help='BPF filtresi (örn. "tcp port 80")')
    
    # Filtreleme seçenekleri                    
    parser.add_argument('-p', '--port', type=int, nargs='+', 
                        help='Port numaraları (örn. 80 443 8080)')
    parser.add_argument('-ip', '--ip', nargs='+', 
                        help='IP adresleri (örn. 192.168.1.1)')
    parser.add_argument('-n', '--net', nargs='+', 
                        help='Ağ adresleri (örn. 192.168.1.0/24)')
    parser.add_argument('-pr', '--protocol', nargs='+', 
                        choices=['tcp', 'udp', 'icmp'], 
                        help='Protokoller (tcp, udp, icmp)')
    parser.add_argument('-m', '--mac', nargs='+',
                        help='MAC adresleri (örn. 00:11:22:33:44:55)')
    parser.add_argument('--host', nargs='+',
                        help='Hostname veya IP adresleri (örn. google.com)')
    
    # İçerik arama seçenekleri
    parser.add_argument('-k', '--keyword', nargs='+', 
                        help='Aranacak anahtar kelimeler (örn. "login password sifre")')
    parser.add_argument('-r', '--regex', nargs='+',
                        help='Aranacak regex desenleri')
    parser.add_argument('--no-sensitive', action='store_true',
                        help='Hassas veri tespitini devre dışı bırak')
    
    # WiFi seçenekleri
    parser.add_argument('--monitor', action='store_true',
                        help='WiFi monitör modunu etkinleştir')
    parser.add_argument('--ssid', nargs='+',
                        help='Filtre uygulanacak WiFi SSID')
    
    # Çıktı seçenekleri
    parser.add_argument('-s', '--stats', action='store_true', 
                        help='Periyodik istatistik göster')
    parser.add_argument('--stats-interval', type=int, default=10,
                        help='İstatistik gösterme sıklığı (saniye)')
    parser.add_argument('-q', '--quiet', action='store_true', 
                        help='Sessiz mod, sadece önemli paketleri göster')
    parser.add_argument('--no-banner', action='store_true',
                        help='Banner gösterme')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Detaylı çıktı göster')
    parser.add_argument('--format', choices=['text', 'json', 'pcap'], default='text',
                        help='Çıktı formatı (text, json, pcap)')
    
    return parser.parse_args()

def check_root():
    """Root yetkisi kontrolü yap"""
    if os.name == 'posix' and os.geteuid() != 0:
        UI.print_error("Bu programı çalıştırmak için yönetici (root) yetkileri gereklidir.")
        UI.print_info(f"Örnek: sudo python3 {os.path.basename(__file__)}")
        return False
    return True

def main():
    """Ana fonksiyon"""
    # Argümanları ayrıştır
    args = parse_arguments()
    
    # Root kontrolü
    if not check_root():
        return
    
    # PacketMaster'ı başlat
    packet_master = PacketMaster(args)
    packet_master.start()

if __name__ == "__main__":
    main()