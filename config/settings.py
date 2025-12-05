import json
import os
from pathlib import Path
from dotenv import load_dotenv

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

CONFIG_FILE = Path("data/config. json")
CONFIG_FILE.parent.mkdir(exist_ok=True)

def load_config():
    """Carrega configuração do arquivo ou variáveis de ambiente"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    
    return {
        'virustotal_api_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
        'abuseipdb_api_key': os.getenv('ABUSEIPDB_API_KEY', ''),
        'shodan_api_key': os.getenv('SHODAN_API_KEY', ''),
        'ipinfo_token': os.getenv('IPINFO_TOKEN', ''),
        'greynoise_api_key': os.getenv('GREYNOISE_API_KEY', ''),
        'ipqualityscore_api_key': os.getenv('IPQUALITYSCORE_API_KEY', ''),
    }

def save_config(config):
    """Salva configuração em arquivo JSON"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)