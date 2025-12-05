import requests
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class IPInfoService:
    """Serviço para integração com IPinfo API"""
    
    def __init__(self, token: str):
        self.token = token
        self.base_url = "https://ipinfo. io"
        self.timeout = 10
    
    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        """
        Obtém informações detalhadas de um IP
        
        Args:
            ip: Endereço IP a ser pesquisado
            
        Returns:
            Dict com informações do IP
        """
        try:
            url = f"{self.base_url}/{ip}/json"
            params = {"token": self.token} if self.token else {}
            
            response = requests.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response. json()
                
                # Extrai coordenadas se disponíveis
                coordinates = None
                if 'loc' in data:
                    try:
                        coords = data['loc'].split(',')
                        coordinates = {'latitude': float(coords[0]), 'longitude': float(coords[1])}
                    except:
                        coordinates = None
                
                return {
                    'status': 'success',
                    'ip': data. get('ip'),
                    'hostname': data.get('hostname', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'region': data.get('region', 'N/A'),
                    'country': data.get('country', 'N/A'),
                    'country_name': self._get_country_name(data. get('country', '')),
                    'latitude': coordinates['latitude'] if coordinates else None,
                    'longitude': coordinates['longitude'] if coordinates else None,
                    'timezone': data.get('timezone', 'N/A'),
                    'isp': data.get('org', 'N/A'),
                    'asn': self._extract_asn(data.get('org', '')),
                    'privacy': {
                        'vpn': data.get('privacy', {}).get('vpn', False),
                        'proxy': data.get('privacy', {}).get('proxy', False),
                        'tor': data.get('privacy', {}).get('tor', False),
                        'relay': data.get('privacy', {}).get('relay', False),
                    }
                }
            elif response.status_code == 401:
                return {'status': 'error', 'message': 'Token de IPinfo inválido'}
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except requests. exceptions.Timeout:
            return {'status': 'error', 'message': 'Timeout ao conectar ao IPinfo'}
        except Exception as e:
            logger.error(f"Erro ao consultar IPinfo para {ip}: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def get_batch_info(self, ips: list) -> Dict[str, Any]:
        """
        Obtém informações em lote (máximo 50 IPs)
        
        Args:
            ips: Lista de IPs (máximo 50)
            
        Returns:
            Dict com informações dos IPs
        """
        try:
            if len(ips) > 50:
                return {'status': 'error', 'message': 'Máximo de 50 IPs por requisição'}
            
            url = f"{self.base_url}/batch"
            params = {"token": self.token} if self.token else {}
            
            response = requests.post(
                url,
                data='\n'.join(ips),
                params=params,
                timeout=self.timeout,
                headers={'Content-Type': 'text/plain'}
            )
            
            if response. status_code == 200:
                results = response.json()
                return {
                    'status': 'success',
                    'count': len(results),
                    'results': results
                }
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            logger.error(f"Erro ao consultar IPinfo em lote: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def get_asn_info(self, asn: str) -> Dict[str, Any]:
        """
        Obtém informações sobre um ASN
        
        Args:
            asn: Número do ASN (ex: 'AS15169')
            
        Returns:
            Dict com informações do ASN
        """
        try:
            # Garante que tem o prefixo AS
            if not asn.startswith('AS'):
                asn = f'AS{asn}'
            
            url = f"{self. base_url}/{asn}/json"
            params = {"token": self.token} if self.token else {}
            
            response = requests.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response. json()
                
                return {
                    'status': 'success',
                    'asn': data.get('asn'),
                    'name': data.get('name', 'N/A'),
                    'country': data.get('country', 'N/A'),
                    'allocated': data.get('allocated', 'N/A'),
                    'registry': data.get('registry', 'N/A'),
                    'domain': data.get('domain', 'N/A'),
                    'num_prefixes': data.get('num_prefixes', 0),
                    'num_ips': data.get('num_ips', 0),
                }
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            logger. error(f"Erro ao obter informações do ASN: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def _extract_asn(org_string: str) -> str:
        """Extrai o ASN da string de organização"""
        try:
            if 'AS' in org_string:
                return org_string.split()[0]
        except:
            pass
        return 'N/A'
    
    @staticmethod
    def _get_country_name(country_code: str) -> str:
        """Converte código de país em nome"""
        countries = {
            'US': 'United States',
            'BR': 'Brazil',
            'GB': 'United Kingdom',
            'DE': 'Germany',
            'FR': 'France',
            'JP': 'Japan',
            'CN': 'China',
            'IN': 'India',
            'RU': 'Russia',
            'CA': 'Canada',
        }
        return countries.get(country_code, country_code)