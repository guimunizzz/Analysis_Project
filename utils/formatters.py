import pandas as pd
from typing import List, Dict, Any
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ResultFormatter:
    """Classe para formatar resultados de análises"""
    
    @staticmethod
    def format_ip_results(results: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Formata resultados de análise de IP para DataFrame
        
        Args:
            results: Lista de resultados de análise de IP
            
        Returns:
            DataFrame formatado
        """
        try:
            formatted_data = []
            
            for result in results:
                formatted_data.append({
                    'IP': result. get('ip', 'N/A'),
                    'VirusTotal Reputation': result.get('reputation', 0),
                    'VT Malicious': result.get('last_analysis_stats', {}).get('malicious', 0),
                    'VT Suspicious': result.get('last_analysis_stats', {}).get('suspicious', 0),
                    'AbuseIPDB Score': result.get('abuse_confidence_score', 'N/A'),
                    'AbuseIPDB Reports': result.get('total_reports', 0),
                    'Shodan Ports': len(result.get('ports', [])),
                    'Country': result.get('country', 'N/A'),
                    'ISP': result.get('isp', 'N/A'),
                    'Status': ResultFormatter._determine_status(result),
                    'Timestamp': datetime.now().isoformat()
                })
            
            return pd.DataFrame(formatted_data)
        except Exception as e:
            logger.error(f"Erro ao formatar resultados de IP: {str(e)}")
            return pd.DataFrame()
    
    @staticmethod
    def format_hash_results(results: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Formata resultados de análise de Hash para DataFrame
        
        Args:
            results: Lista de resultados de análise de hash
            
        Returns:
            DataFrame formatado
        """
        try:
            formatted_data = []
            
            for result in results:
                formatted_data.append({
                    'Hash': result.get('hash', 'N/A'),
                    'Type': result.get('type', 'Unknown'),
                    'File Type': result.get('file_type', 'N/A'),
                    'Detections (VT)': result.get('detections', 0),
                    'Total Scans': result.get('total_scans', 0),
                    'Status': result.get('status', 'Unknown'),
                    'Last Analysis Date': ResultFormatter._format_timestamp(result.get('last_analysis_date')),
                    'Timestamp': datetime.now().isoformat()
                })
            
            return pd.DataFrame(formatted_data)
        except Exception as e:
            logger.error(f"Erro ao formatar resultados de hash: {str(e)}")
            return pd.DataFrame()
    
    @staticmethod
    def format_domain_results(results: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Formata resultados de análise de Domínio para DataFrame
        
        Args:
            results: Lista de resultados de análise de domínio
            
        Returns:
            DataFrame formatado
        """
        try:
            formatted_data = []
            
            for result in results:
                formatted_data.append({
                    'Domain': result.get('domain', 'N/A'),
                    'Reputation': result.get('reputation', 0),
                    'Malicious Count': result.get('malicious_count', 0),
                    'Suspicious Count': result.get('suspicious_count', 0),
                    'Status': result.get('status', 'Unknown'),
                    'Created Date': ResultFormatter._format_timestamp(result.get('whois_creation_date')),
                    'Last Analysis': ResultFormatter._format_timestamp(result.get('last_analysis_date')),
                    'Timestamp': datetime.now().isoformat()
                })
            
            return pd.DataFrame(formatted_data)
        except Exception as e:
            logger.error(f"Erro ao formatar resultados de domínio: {str(e)}")
            return pd.DataFrame()
    
    @staticmethod
    def format_for_csv(data: List[Dict[str, Any]], filename: str = None) -> str:
        """
        Formata dados para exportação CSV
        
        Args:
            data: Lista de dados
            filename: Nome do arquivo (opcional)
            
        Returns:
            String CSV
        """
        try:
            df = pd.DataFrame(data)
            return df.to_csv(index=False)
        except Exception as e:
            logger.error(f"Erro ao formatar para CSV: {str(e)}")
            return ""
    
    @staticmethod
    def format_for_json(data: Any) -> str:
        """
        Formata dados para exportação JSON
        
        Args:
            data: Dados a serem formatados
            
        Returns:
            String JSON formatada
        """
        try:
            return json.dumps(data, indent=2, default=str)
        except Exception as e:
            logger.error(f"Erro ao formatar para JSON: {str(e)}")
            return "{}"
    
    @staticmethod
    def format_for_txt(results: List[Dict[str, Any]], result_type: str = 'ip') -> str:
        """
        Formata resultados para exportação de texto simples
        
        Args:
            results: Lista de resultados
            result_type: Tipo de resultado ('ip', 'hash', 'domain')
            
        Returns:
            String formatada para texto
        """
        try:
            lines = []
            lines.append("=" * 80)
            lines.append(f"Relatório de Análise - {result_type.upper()}")
            lines.append(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            lines.append("=" * 80)
            lines.append("")
            
            if result_type == 'ip':
                for result in results:
                    lines.append(f"IP: {result.get('ip', 'N/A')}")
                    lines.append(f"  País: {result.get('country', 'N/A')}")
                    lines.append(f"  ISP: {result.get('isp', 'N/A')}")
                    lines. append(f"  Reputação (VT): {result.get('reputation', 0)}")
                    lines.append(f"  Score (AbuseIPDB): {result.get('abuse_confidence_score', 'N/A')}")
                    lines.append(f"  Portos (Shodan): {len(result.get('ports', []))}")
                    lines.append("-" * 40)
                    lines.append("")
            
            elif result_type == 'hash':
                for result in results:
                    lines.append(f"Hash: {result.get('hash', 'N/A')}")
                    lines.append(f"  Tipo: {result. get('type', 'Unknown')}")
                    lines.append(f"  Detecções (VT): {result.get('detections', 0)}/{result.get('total_scans', 0)}")
                    lines.append(f"  Status: {result.get('status', 'Unknown')}")
                    lines.append("-" * 40)
                    lines.append("")
            
            elif result_type == 'domain':
                for result in results:
                    lines.append(f"Domínio: {result.get('domain', 'N/A')}")
                    lines.append(f"  Reputação: {result.get('reputation', 0)}")
                    lines. append(f"  Maliciosos (VT): {result.get('malicious_count', 0)}")
                    lines.append(f"  Status: {result.get('status', 'Unknown')}")
                    lines.append("-" * 40)
                    lines.append("")
            
            lines.append("=" * 80)
            return "\n".join(lines)
        except Exception as e:
            logger.error(f"Erro ao formatar para TXT: {str(e)}")
            return ""
    
    @staticmethod
    def _determine_status(ip_result: Dict[str, Any]) -> str:
        """Determina o status de um IP baseado em várias fontes"""
        abuse_score = ip_result.get('abuse_confidence_score', 0)
        vt_malicious = ip_result.get('last_analysis_stats', {}). get('malicious', 0)
        
        if abuse_score > 75 or vt_malicious > 5:
            return '🔴 Malicious'
        elif abuse_score > 25 or vt_malicious > 0:
            return '🟡 Suspicious'
        else:
            return '🟢 Clean'
    
    @staticmethod
    def _format_timestamp(timestamp: Any) -> str:
        """Formata um timestamp para data legível"""
        try:
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp). strftime('%d/%m/%Y')
            elif isinstance(timestamp, str):
                return timestamp. split('T')[0]
        except:
            pass
        return 'N/A'
    
    @staticmethod
    def create_summary(results: List[Dict[str, Any]], result_type: str = 'ip') -> Dict[str, Any]:
        """
        Cria um resumo dos resultados
        
        Args:
            results: Lista de resultados
            result_type: Tipo de resultado
            
        Returns:
            Dict com estatísticas dos resultados
        """
        try:
            summary = {
                'total_analyzed': len(results),
                'timestamp': datetime.now().isoformat(),
                'result_type': result_type
            }
            
            if result_type == 'ip':
                malicious_count = sum(1 for r in results if r.get('last_analysis_stats', {}).get('malicious', 0) > 0)
                summary['malicious'] = malicious_count
                summary['clean'] = len(results) - malicious_count
                summary['avg_reputation'] = sum(r. get('reputation', 0) for r in results) / len(results) if results else 0
            
            elif result_type == 'hash':
                malicious_count = sum(1 for r in results if r.get('detections', 0) > 0)
                summary['malicious'] = malicious_count
                summary['clean'] = len(results) - malicious_count
            
            elif result_type == 'domain':
                malicious_count = sum(1 for r in results if r.get('malicious_count', 0) > 0)
                summary['malicious'] = malicious_count
                summary['clean'] = len(results) - malicious_count
            
            return summary
        except Exception as e:
            logger. error(f"Erro ao criar resumo: {str(e)}")
            return {}