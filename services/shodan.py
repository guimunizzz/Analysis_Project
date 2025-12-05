import requests
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class ShodanService:
    """Serviço para integração com Shodan API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self. base_url = "https://api.shodan.io"
        self.timeout = 10
    
    def search_host(self, ip: str) -> Dict[str, Any]:
        """
        Busca informações de um host no Shodan
        
        Args:
            ip: Endereço IP a ser pesquisado
            
        Returns:
            Dict com informações do host ou status de erro
        """
        try:
            url = f"{self.base_url}/shodan/host/{ip}"
            params = {"key": self.api_key}
            
            response = requests. get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'status': 'success',
                    'ip': ip,
                    'ports': data.get('ports', []),
                    'hostnames': data.get('hostnames', []),
                    'tags': data.get('tags', []),
                    'os': data.get('os'),
                    'isp': data.get('isp', 'N/A'),
                    'organization': data.get('org', 'N/A'),
                    'asn': data. get('asn', 'N/A'),
                    'last_update': data.get('last_update'),
                    'services_count': len(data.get('ports', [])),
                }
            elif response.status_code == 401:
                return {'status': 'error', 'message': 'Chave de API inválida'}
            elif response.status_code == 404:
                return {'status': 'not_found', 'ip': ip, 'message': 'IP não encontrado no Shodan'}
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}: {response.text}"}
        
        except requests.exceptions.Timeout:
            return {'status': 'error', 'message': 'Timeout ao conectar ao Shodan'}
        except Exception as e:
            logger.error(f"Erro ao consultar Shodan para {ip}: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def get_account_info(self) -> Dict[str, Any]:
        """Obtém informações da conta Shodan"""
        try:
            url = f"{self.base_url}/account/profile"
            params = {"key": self.api_key}
            
            response = requests.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'success',
                    'credits_remaining': data.get('credits', 0),
                    'tier': data.get('plan', 'Unknown'),
                    'email': data.get('email', 'N/A'),
                }
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Erro ao obter informações da conta Shodan: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def search_query(self, query: str, page: int = 1) -> Dict[str, Any]:
        """
        Realiza uma busca no Shodan
        
        Args:
            query: String de busca (ex: "port:22 country:US")
            page: Número da página
            
        Returns:
            Resultados da busca
        """
        try:
            url = f"{self.base_url}/shodan/host/search"
            params = {
                "key": self.api_key,
                "query": query,
                "page": page
            }
            
            response = requests.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'status': 'success',
                    'total_results': data.get('total', 0),
                    'matches': data.get('matches', []),
                    'page': page,
                }
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            logger. error(f"Erro ao buscar no Shodan: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def get_services_info(self, ip: str, port: int) -> Dict[str, Any]:
        """Obtém informações detalhadas de um serviço específico"""
        try:
            host_info = self.search_host(ip)
            
            if host_info. get('status') != 'success':
                return host_info
            
            # Procura informações do porto específico
            for port_data in host_info.get('ports', []):
                if port_data == port:
                    return {
                        'status': 'success',
                        'ip': ip,
                        'port': port,
                        'found': True
                    }
            
            return {
                'status': 'not_found',
                'ip': ip,
                'port': port,
                'found': False,
                'message': f'Porta {port} não encontrada neste IP'
            }
        
        except Exception as e:
            logger.error(f"Erro ao obter informações do serviço: {str(e)}")
            return {'status': 'error', 'message': str(e)}