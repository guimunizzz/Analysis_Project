import streamlit as st
import pandas as pd
from pathlib import Path
import json
from datetime import datetime
from config.settings import load_config, save_config
from services.virustotal import VirusTotalService
from services.abuseipdb import AbuseIPDBService
from utils.validators import validate_ip, validate_hash, validate_domain

# Configuração da página
st.set_page_config(
    page_title="The Operator - Streamlit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado
st.markdown("""
    <style>
    .main { padding: 2rem; }
    .stMetric { background-color: #f0f2f6; border-radius: 8px; padding: 1rem; }
    </style>
""", unsafe_allow_html=True)

def initialize_session():
    """Inicializa variáveis de sessão"""
    if 'config' not in st.session_state:
        st.session_state.config = load_config()
    if 'blocklist_ips' not in st.session_state:
        st.session_state.blocklist_ips = []
    if 'blocklist_hashes' not in st.session_state:
        st.session_state.blocklist_hashes = []
    if 'blocklist_domains' not in st.session_state:
        st.session_state.blocklist_domains = []

def main():
    """Função principal"""
    initialize_session()
    
    # Header
    st.title("🛡️ The Operator - Inteligência de Ameaças")
    st.markdown("Plataforma de análise de segurança com integração a múltiplas fontes")
    
    # Verificar se APIs estão configuradas
    config = st.session_state.config
    
    with st.sidebar:
        st.header("Configuração")
        
        if not config.get('virustotal_api_key'):
            st.warning("⚠️ Nenhuma API configurada. Acesse Configurações para adicionar suas chaves.")
        else:
            st.success("✅ APIs configuradas")
        
        # Links para as páginas
        st.markdown("---")
        st.markdown("### Ferramentas")
        
        pages = {
            "🔍 Análise de IP": "ip_analysis",
            "🔗 Análise de Hash": "hash_analysis",
            "🌐 Análise de Domínio": "domain_analysis",
            "📋 Listas de Bloqueio": "blocklists",
            "⚙️ Configurações": "settings"
        }
    
    # Conteúdo principal
    st.markdown("---")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("IPs Analisados", "0", delta="Esta sessão")
    
    with col2:
        st.metric("Hashes Verificados", "0", delta="Esta sessão")
    
    with col3:
        st.metric("Domínios Checados", "0", delta="Esta sessão")
    
    st.markdown("---")
    st.markdown("### 🚀 Bem-vindo ao The Operator")
    st.markdown("""
    Use as abas acima para:
    - **Análise de IP**: Verificar reputação de endereços IP
    - **Análise de Hash**: Validar hashes de arquivos (MD5, SHA1, SHA256)
    - **Análise de Domínio**: Investigar domínios e URLs maliciosos
    - **Listas de Bloqueio**: Gerenciar IPs, hashes e domínios bloqueados
    - **Configurações**: Adicionar suas chaves de API
    """)

if __name__ == "__main__":
    main()