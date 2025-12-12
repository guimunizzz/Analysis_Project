import streamlit as st
import pandas as pd
from pathlib import Path
import json
from datetime import datetime
from config.settings import load_config, save_config
from services.virustotal import VirusTotalService
from services.abuseipdb import AbuseIPDBService
from utils.validators import validate_ip, validate_hash, validate_domain
from styles.theme import get_common_styles, get_sidebar_logo_html

# Configuração da página
st.set_page_config(
    page_title="Sec Analysis - Streamlit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado - usando tema centralizado
st.markdown(get_common_styles(), unsafe_allow_html=True)

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
    st.title("🛡️ Sec Analysis - Inteligência de Ameaças")
    st.markdown("Plataforma de análise de segurança com integração a múltiplas fontes")
    
    # Verificar se APIs estão configuradas
    config = st.session_state.config
    
    with st.sidebar:
        # Add logo at the top of sidebar
        st.markdown(get_sidebar_logo_html(), unsafe_allow_html=True)
        
        st.header("Configuração")
        
        if not config.get('virustotal_api_key'):
            st.warning("⚠️ Nenhuma API configurada. Acesse Configurações para adicionar suas chaves.")
        else:
            st.success("✅ APIs configuradas")
        
        
        pages = {
            "🔍 Análise de IP": "ip_analysis",
            "🔗 Análise de Hash": "hash_analysis",
            "🌐 Análise de Domínio": "domain_analysis",
            "📋 Listas de Bloqueio": "blocklists",
        }
    
    # Conteúdo principal
    st.markdown("---")
    
    # Cards de métricas com o novo estilo
    st.markdown("""
        <div class="card-row">
            <div class="card">
                <div class="card-label">IPs Analisados</div>
                <div class="card-value">0</div>
                <div class="card-sub">Esta sessão</div>
            </div>
            <div class="card">
                <div class="card-label">Hashes Verificados</div>
                <div class="card-value">0</div>
                <div class="card-sub">Esta sessão</div>
            </div>
            <div class="card">
                <div class="card-label">Domínios Checados</div>
                <div class="card-value">0</div>
                <div class="card-sub">Esta sessão</div>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Seção de boas-vindas com cards
    st.markdown("""
        <div class="page-shell">
            <div class="page-shell-header">
                <div>
                    <div class="page-shell-title">
                        🚀 Bem-vindo ao Sec Analysis
                    </div>
                    <div class="page-shell-subtitle">
                        Plataforma integrada de inteligência de ameaças para análise de segurança
                    </div>
                </div>
                <span class="page-shell-badge">THREAT INTELLIGENCE</span>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Cards de ferramentas disponíveis
    st.markdown("### 🔧 Ferramentas Disponíveis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
            <div class="card">
                <div class="card-label">🔍 Análise de IP</div>
                <div class="card-sub">Verificar reputação de endereços IP em múltiplas fontes</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
            <div class="card">
                <div class="card-label">🔗 Análise de Hash</div>
                <div class="card-sub">Validar hashes de arquivos (MD5, SHA1, SHA256)</div>
            </div>
        """, unsafe_allow_html=True)
        
    
    with col2:
        st.markdown("""
            <div class="card">
                <div class="card-label">📋 Listas de Bloqueio</div>
                <div class="card-sub">Gerenciar IPs, hashes e domínios bloqueados</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
            <div class="card">
                <div class="card-label">🌐 Análise de Domínio</div>
                <div class="card-sub">Investigar domínios e URLs maliciosos</div>
            </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()