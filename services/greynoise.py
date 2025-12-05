import requests
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class GreyNoiseService:
    """Serviço para integração com GreyNoise API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.greynoise.io/v3"
        self.timeout = 10
        self.headers = {
            "key": api_key,
            "User-Agent": "The-Operator-Streamlit"
        }
    
    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        """
        Obtém informações de um IP no GreyNoise
        
        Args:
            ip: Endereço IP a ser pesquisado
            
        Returns:
            Dict com informações do IP
        """
        try:
            url = f"{self.base_url}/ip/{ip}"
            
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'status': 'success',
                    'ip': ip,
                    'classification': data.get('classification', 'unknown'),
                    'is_malicious': data.get('classification') == 'malicious',
                    'first_seen': data.get('first_seen'),
                    'last_seen': data.get('last_seen'),
                    'tags': data.get('tags', []),
                    'seen_in_attacks': data.get('seen_in_attacks', False),
                    'name': data.get('name', 'N/A'),
                    'noise_level': data.get('noise', False),
                    'riot': data.get('riot', False),  # RIOT = Reconnaissance Intelligence Operated Threat
                    'services_observed': data.get('services_observed', []),
                    'last_activity': data.get('last_activity', {}).get('timestamp'),
                    'spoofable': data.get('spoofable', False),
                }
            elif response.status_code == 401:
                return {'status': 'error', 'message': 'Chave de API do GreyNoise inválida'}
            elif response.status_code == 404:
                return {'status': 'not_found', 'ip': ip, 'message': 'IP não encontrado no GreyNoise'}
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except requests.exceptions.Timeout:
            return {'status': 'error', 'message': 'Timeout ao conectar ao GreyNoise'}
        except Exception as e:
            logger.error(f"Erro ao consultar GreyNoise para {ip}: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def get_bulk_info(self, ips: list) -> Dict[str, Any]:
        """
        Obtém informações em lote de múltiplos IPs
        
        Args:
            ips: Lista de IPs
            
        Returns:
            Dict com informações dos IPs
        """
        try:
            url = f"{self.base_url}/bulk/ips"
            
            payload = {
                "ips": ips,
                "source": "external"
            }
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'status': 'success',
                    'count': len(data. get('ips', [])),
                    'results': data. get('ips', [])
                }
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Erro ao consultar GreyNoise em lote: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def get_community_ip_info(self, ip: str) -> Dict[str, Any]:
        """
        Obtém informações de um IP usando a API Community (gratuita, limitado)
        
        Args:
            ip: Endereço IP a ser pesquisado
            
        Returns:
            Dict com informações básicas do IP
        """
        try:
            url = f"https://api.greynoise.io/v3/community/{ip}"
            
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'status': 'success',
                    'ip': ip,
                    'classification': data.get('classification', 'unknown'),
                    'is_malicious': data.get('classification') == 'malicious',
                    'name': data.get('name', 'N/A'),
                    'description': data.get('description', 'N/A'),
                    'tags': data.get('tags', []),
                    'intent': data.get('intent', 'N/A'),
                    'source_url': data.get('source_url', ''),
                }
            elif response.status_code == 404:
                return {'status': 'not_found', 'ip': ip}
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Erro ao consultar GreyNoise Community para {ip}: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def query_ips(self, query: str, limit: int = 100) -> Dict[str, Any]:
        """
        Busca IPs usando query (requer plano pago)
        
        Args:
            query: Query string (ex: "classification:malicious country:CN")
            limit: Limite de resultados
            
        Returns:
            Dict com IPs encontrados
        """
        try:
            url = f"{self.base_url}/ips"
            params = {
                "query": query,
                "limit": limit
            }
            
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'status': 'success',
                    'count': data.get('count', 0),
                    'results': data. get('ips', [])
                }
            else:
                return {'status': 'error', 'message': f"Erro {response. status_code}"}
        
        except Exception as e:
            logger.error(f"Erro ao fazer query no GreyNoise: {str(e)}")
            return {'status': 'error', 'message': str(e)}