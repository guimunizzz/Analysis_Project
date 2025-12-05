import requests
import streamlit as st
from typing import Dict, Any
import time
import logging

logger = logging.getLogger(__name__)

class VirusTotalService:
    """Serviço para integração com VirusTotal API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self. base_url = "https://www.virustotal.com/api/v3"
        self. headers = {
            "x-apikey": api_key,
            "User-Agent": "The-Operator-Streamlit"
        }
    
    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analisa um IP no VirusTotal"""
        try:
            url = f"{self.base_url}/ip_addresses/{ip}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                return {
                    'status': 'success',
                    'ip': ip,
                    'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                    'country': attributes.get('country', 'N/A'),
                    'asn': attributes.get('asn', 'N/A'),
                    'reputation': attributes.get('reputation', 0),
                }
            elif response.status_code == 404:
                return {'status': 'not_found', 'ip': ip}
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Erro ao consultar VirusTotal para {ip}: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def analyze_hash(self, hash_value: str) -> Dict[str, Any]:
        """Analisa um hash no VirusTotal com detalhes completos"""
        try:
            url = f"{self.base_url}/files/{hash_value}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response. status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                stats = attributes.get('last_analysis_stats', {})
                last_analysis_results = attributes.get('last_analysis_results', {})
                
                # Extrair vendors que detectaram como malware
                detected_vendors = []
                threat_categories = set()
                family_labels = {}
                
                for vendor, result in last_analysis_results.items():
                    category = result.get('category', 'undetected')
                    
                    # Se foi detectado (não é undetected ou harmless)
                    if category in ['malicious', 'suspicious']:
                        detected_vendors.append({
                            'vendor': vendor,
                            'category': category,
                            'engine_name': result.get('engine_name', vendor),
                            'result': result.get('result', 'N/A'),
                            'engine_update': result.get('engine_update', 'N/A')
                        })
                        
                        # Coletar threat categories
                        if result.get('category'):
                            threat_categories.add(result. get('category'))
                    
                    # Coletar family labels
                    if result. get('result'):
                        family_name = result.get('result', '').split('/')[0] if '/' in result.get('result', '') else result.get('result', '')
                        if family_name and family_name not in ['Undetected', 'undetected', 'Trojan']:
                            family_labels[family_name] = family_labels.get(family_name, 0) + 1
                
                # Ordenar vendors por número de detecções
                detected_vendors = sorted(detected_vendors, key=lambda x: 1 if x['category'] == 'malicious' else 0, reverse=True)
                
                return {
                    'status': 'success',
                    'hash': hash_value,
                    'file_type': attributes.get('type_description', 'N/A'),
                    'detections': stats. get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_scans': sum(stats.values()),
                    'last_analysis_date': attributes.get('last_analysis_date'),
                    'size': attributes.get('size', 'N/A'),
                    'magic': attributes.get('magic', 'N/A'),
                    'sha256': attributes.get('sha256', 'N/A'),
                    'sha1': attributes. get('sha1', 'N/A'),
                    'md5': attributes.get('md5', 'N/A'),
                    'names': attributes.get('names', []),
                    'detected_vendors': detected_vendors,  # Vendors que detectaram
                    'threat_categories': list(threat_categories),  # Categorias de ameaça
                    'family_labels': family_labels,  # Famílias detectadas
                    'last_analysis_results': last_analysis_results  # Todos os resultados brutos
                }
            elif response.status_code == 404:
                return {'status': 'not_found', 'hash': hash_value}
            else:
                logger.error(f"Erro ao analisar hash: {response.status_code} - {response.text}")
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except requests.exceptions. Timeout:
            return {'status': 'error', 'message': 'Timeout ao conectar ao VirusTotal'}
        except Exception as e:
            logger.error(f"Erro ao consultar VirusTotal para {hash_value}: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analisa um domínio no VirusTotal"""
        try:
            url = f"{self.base_url}/domains/{domain}"
            response = requests. get(url, headers=self. headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}). get('attributes', {})
                
                stats = attributes.get('last_analysis_stats', {})
                return {
                    'status': 'success',
                    'domain': domain,
                    'reputation': attributes.get('reputation', 0),
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'categories': attributes.get('categories', {}),
                    'last_analysis_date': attributes.get('last_analysis_date'),
                }
            elif response.status_code == 404:
                return {'status': 'not_found', 'domain': domain}
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Erro ao consultar VirusTotal para {domain}: {str(e)}")
            return {'status': 'error', 'message': str(e)}