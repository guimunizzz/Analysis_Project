import re
from typing import List, Tuple

def validate_ip(ip: str) -> bool:
    """Valida um endereço IP (IPv4 ou IPv6)"""
    ip_clean = ip.strip()
    
    # Método simples: dividir por pontos e validar cada octeto
    parts = ip_clean.split('.')
    
    if len(parts) == 4:
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except ValueError:
            pass
    
    # Se não for IPv4 válido, testar IPv6
    try:
        # IPv6 simples
        if ':' in ip_clean:
            return True
    except:
        pass
    
    return False

def validate_hash(hash_value: str) -> Tuple[bool, str]:
    """Valida um hash e retorna seu tipo"""
    hash_value = hash_value.strip(). lower()
    
    if len(hash_value) == 32 and re.match(r'^[a-f0-9]{32}$', hash_value):
        return True, 'MD5'
    elif len(hash_value) == 40 and re.match(r'^[a-f0-9]{40}$', hash_value):
        return True, 'SHA1'
    elif len(hash_value) == 64 and re. match(r'^[a-f0-9]{64}$', hash_value):
        return True, 'SHA256'
    
    return False, 'Unknown'

def validate_domain(domain: str) -> bool:
    """Valida um nome de domínio"""
    domain_clean = domain.strip(). lower()
    domain_pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$'
    return bool(re.match(domain_pattern, domain_clean))

def parse_ips_from_text(text: str) -> List[str]:
    """Extrai IPs de um texto"""
    ipv4_pattern = r'\b(?:(? :25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]? [0-9][0-9]?)\b'
    matches = re.findall(ipv4_pattern, text)
    return list(set(matches))

def parse_hashes_from_text(text: str) -> List[Tuple[str, str]]:
    """Extrai hashes de um texto"""
    hashes = []
    
    for match in re.finditer(r'\b[a-fA-F0-9]{32}\b', text):
        hashes. append((match.group().lower(), 'MD5'))
    
    for match in re.finditer(r'\b[a-fA-F0-9]{40}\b', text):
        hashes.append((match.group(). lower(), 'SHA1'))
    
    for match in re. finditer(r'\b[a-fA-F0-9]{64}\b', text):
        hashes.append((match. group().lower(), 'SHA256'))
    
    return list(set(hashes))

def parse_domains_from_text(text: str) -> List[str]:
    """Extrai domínios de um texto"""
    domain_pattern = r'(?:https?://)?(?:www\. )?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](? :[a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,})'
    matches = re.findall(domain_pattern, text. lower())
    return list(set(matches))

def parse_urls_from_text(text: str) -> List[str]:
    """Extrai URLs de um texto"""
    url_pattern = r'https?://[^\s]+'
    matches = re.findall(url_pattern, text)
    return list(set(matches))

def parse_emails_from_text(text: str) -> List[str]:
    """Extrai emails de um texto"""
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    matches = re.findall(email_pattern, text)
    return list(set(matches))