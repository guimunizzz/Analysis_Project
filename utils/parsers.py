import re
from typing import List, Tuple, Set
import logging

logger = logging.getLogger(__name__)

class TextParser:
    """Classe para extrair diferentes tipos de indicadores de um texto"""
    
    # Padrões Regex
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    IPV6_PATTERN = r'(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})'
    
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    
    DOMAIN_PATTERN = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}'
    URL_PATTERN = r'https? ://[^\s]+'
    EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    @staticmethod
    def parse_ips(text: str) -> List[str]:
        """
        Extrai todos os endereços IP (IPv4 e IPv6) de um texto
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            Lista de IPs únicos
        """
        try:
            # IPv4
            ipv4_matches = re.finditer(TextParser.IPV4_PATTERN, text)
            ips = list(set([match.group() for match in ipv4_matches]))
            
            # IPv6
            ipv6_matches = re.finditer(TextParser.IPV6_PATTERN, text)
            ips.extend(list(set([match.group() for match in ipv6_matches])))
            
            return list(set(ips))
        except Exception as e:
            logger. error(f"Erro ao fazer parse de IPs: {str(e)}")
            return []
    
    @staticmethod
    def parse_hashes(text: str) -> List[Tuple[str, str]]:
        """
        Extrai hashes (MD5, SHA1, SHA256) de um texto
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            Lista de tuplas (hash, tipo)
        """
        try:
            hashes = []
            
            # MD5
            for match in re.finditer(TextParser.MD5_PATTERN, text):
                hash_value = match.group(). lower()
                hashes.append((hash_value, 'MD5'))
            
            # SHA1
            for match in re.finditer(TextParser.SHA1_PATTERN, text):
                hash_value = match.group().lower()
                hashes.append((hash_value, 'SHA1'))
            
            # SHA256
            for match in re.finditer(TextParser.SHA256_PATTERN, text):
                hash_value = match.group().lower()
                hashes.append((hash_value, 'SHA256'))
            
            # Remove duplicatas
            return list(set(hashes))
        except Exception as e:
            logger.error(f"Erro ao fazer parse de hashes: {str(e)}")
            return []
    
    @staticmethod
    def parse_domains(text: str) -> List[str]:
        """
        Extrai domínios de um texto
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            Lista de domínios únicos
        """
        try:
            # Remove URLs e extrai apenas domínios
            urls = re.findall(TextParser.URL_PATTERN, text)
            text_clean = re.sub(TextParser.URL_PATTERN, ' ', text)
            
            domains = []
            
            # Procura por domínios puros
            for match in re.finditer(TextParser.DOMAIN_PATTERN, text_clean. lower()):
                domain = match.group()
                # Filtra subdomínios menores que 2 caracteres
                if not domain.startswith('.') and domain.count('.') > 0:
                    domains.append(domain)
            
            # Extrai domínios de URLs
            for url in urls:
                domain_match = re.search(TextParser.DOMAIN_PATTERN, url. lower())
                if domain_match:
                    domains.append(domain_match.group())
            
            return list(set(domains))
        except Exception as e:
            logger.error(f"Erro ao fazer parse de domínios: {str(e)}")
            return []
    
    @staticmethod
    def parse_urls(text: str) -> List[str]:
        """
        Extrai URLs de um texto
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            Lista de URLs únicas
        """
        try:
            urls = re.findall(TextParser.URL_PATTERN, text)
            return list(set(urls))
        except Exception as e:
            logger.error(f"Erro ao fazer parse de URLs: {str(e)}")
            return []
    
    @staticmethod
    def parse_emails(text: str) -> List[str]:
        """
        Extrai endereços de email de um texto
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            Lista de emails únicos
        """
        try:
            emails = re.findall(TextParser.EMAIL_PATTERN, text)
            return list(set(emails))
        except Exception as e:
            logger. error(f"Erro ao fazer parse de emails: {str(e)}")
            return []
    
    @staticmethod
    def parse_all_indicators(text: str) -> dict:
        """
        Extrai todos os tipos de indicadores de um texto
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            Dict com todos os indicadores encontrados
        """
        return {
            'ips': TextParser.parse_ips(text),
            'hashes': TextParser.parse_hashes(text),
            'domains': TextParser.parse_domains(text),
            'urls': TextParser.parse_urls(text),
            'emails': TextParser. parse_emails(text),
        }
    
    @staticmethod
    def parse_file(file_path: str) -> dict:
        """
        Extrai indicadores de um arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Dict com todos os indicadores encontrados
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return TextParser.parse_all_indicators(content)
        except Exception as e:
            logger.error(f"Erro ao fazer parse do arquivo {file_path}: {str(e)}")
            return {'ips': [], 'hashes': [], 'domains': [], 'urls': [], 'emails': []}