import requests
from typing import Dict, Any

class AbuseIPDBService:
    """Serviço para integração com AbuseIPDB API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Verifica reputação de um IP no AbuseIPDB"""
        try:
            url = f"{self. base_url}/check"
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                report = data.get('data', {})
                
                return {
                    'status': 'success',
                    'ip': ip,
                    'abuse_confidence_score': report.get('abuseConfidenceScore', 0),
                    'total_reports': report.get('totalReports', 0),
                    'country_code': report.get('countryCode', 'N/A'),
                    'isp': report.get('isp', 'N/A'),
                }
            else:
                return {'status': 'error', 'message': f"Erro {response.status_code}"}
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}