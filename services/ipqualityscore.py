import requests
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class IPQualityScoreService:
    """Serviço para integração com IPQualityScore API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self. base_url = "https://ipqualityscore.com/api/json/ip"
        self.timeout = 10
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Verifica um IP para detectar Proxy, VPN, Tor e outras características de risco
        
        Args:
            ip: Endereço IP a ser verificado
            
        Returns:
            Dict com informações de proxy/VPN e risco
        """
        try:
            # URL: https://ipqualityscore. com/api/json/ip/API_KEY/IP
            url = f"{self.base_url}/{self.api_key}/{ip}"
            
            params = {
                'strictness': 0,
                'allow_public_access_points': 'true'
            }
            
            logger.info(f"Consultando IPQualityScore para IP: {ip}")
            logger.info(f"URL: {url}")
            
            response = requests.get(url, params=params, timeout=self.timeout)
            
            logger.info(f"Status Code: {response.status_code}")
            logger.info(f"Response: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                
                # Verificar se a requisição foi bem-sucedida
                if data.get('success') == False:
                    return {
                        'status': 'error',
                        'message': data.get('message', 'Erro desconhecido'),
                        'ip': ip
                    }
                
                # Mapear os campos conforme a estrutura real da API
                return {
                    'status': 'success',
                    'ip': ip,
                    'fraud_score': data.get('fraud_score', 0),
                    'proxy': data.get('proxy', False),
                    'vpn': data.get('vpn', False),
                    'tor': data. get('tor', False),
                    'active_vpn': data.get('active_vpn', False),
                    'active_tor': data.get('active_tor', False),
                    'is_crawler': data.get('is_crawler', False),
                    'bot_status': data.get('bot_status', False),
                    'is_mobile': data.get('mobile', False),
                    'recent_abuse': data.get('recent_abuse', False),
                    'frequent_abuser': data. get('frequent_abuser', False),
                    'high_risk_attacks': data.get('high_risk_attacks', False),
                    'abuse_velocity': data.get('abuse_velocity', 'N/A'),
                    'shared_connection': data.get('shared_connection', False),
                    'dynamic_connection': data.get('dynamic_connection', False),
                    'security_scanner': data.get('security_scanner', False),
                    'trusted_network': data.get('trusted_network', False),
                    'isp': data.get('ISP', 'N/A'),
                    'organization': data. get('organization', 'N/A'),
                    'country': data.get('country_code', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'region': data. get('region', 'N/A'),
                    'latitude': data.get('latitude'),
                    'longitude': data. get('longitude'),
                    'zip_code': data.get('zip_code', 'N/A'),
                    'timezone': data.get('timezone', 'N/A'),
                    'asn': data.get('ASN', 'N/A'),
                    'host': data.get('host', 'N/A'),
                    'connection_type': data.get('connection_type', 'N/A'),
                    'operating_system': data.get('operating_system', 'N/A'),
                    'browser': data.get('browser', 'N/A'),
                    'device_model': data.get('device_model', 'N/A'),
                    'device_brand': data.get('device_brand', 'N/A'),
                    'request_id': data.get('request_id', 'N/A'),
                    'message': data.get('message', 'N/A'),
                }
            
            elif response.status_code == 400:
                logger.error(f"IP inválido: {ip}")
                return {'status': 'error', 'message': 'IP inválido', 'ip': ip}
            
            elif response.status_code == 401:
                logger. error("Chave de API inválida")
                return {'status': 'error', 'message': 'Chave de API inválida do IPQualityScore'}
            
            elif response.status_code == 429:
                logger.error("Limite de requisições excedido")
                return {'status': 'error', 'message': 'Limite de requisições excedido'}
            
            else:
                logger.error(f"Erro na API IPQualityScore: {response. status_code}")
                return {'status': 'error', 'message': f"Erro {response.status_code}: {response.text}"}
        
        except requests.exceptions. Timeout:
            logger.error("Timeout ao conectar ao IPQualityScore")
            return {'status': 'error', 'message': 'Timeout ao conectar ao IPQualityScore'}
        
        except requests.exceptions.RequestException as e:
            logger. error(f"Erro de requisição: {str(e)}")
            return {'status': 'error', 'message': f"Erro de requisição: {str(e)}"}
        
        except Exception as e:
            logger.error(f"Erro ao consultar IPQualityScore para {ip}: {str(e)}")
            return {'status': 'error', 'message': str(e)}