import streamlit as st
import pandas as pd
from config.    settings import load_config
from services.virustotal import VirusTotalService
from services.abuseipdb import AbuseIPDBService
from services.ipinfo import IPInfoService
from services.  shodan import ShodanService
from services.greynoise import GreyNoiseService
from services.ipqualityscore import IPQualityScoreService
from utils.validators import validate_ip
from utils.   parsers import TextParser
from utils.formatters import ResultFormatter
import time

st.set_page_config(page_title="Análise de IP", page_icon="🔍", layout="wide")

# CSS customizado - Tons de Azul + Alertas Moderados
st.markdown("""
    <style>
    .ip-container {
        background-color: #f0f4f9;
        border: 2px solid #2a5298;
        border-radius: 12px;
        padding: 25px;
        margin: 20px 0;
        color: #1a3a52;
    }
    
    .ip-address {
        font-family: 'Courier New', monospace;
        font-size: 32px;
        font-weight: bold;
        margin: 10px 0;
        letter-spacing: 1px;
        color: #1e3c72;
    }
    
    .risk-score {
        font-size: 18px;
        margin-top: 10px;
        font-weight: 600;
        color: #2a5298;
    }
    
    . alert-section {
        background-color: #fff8f0;
        border-left: 4px solid #ff8c42;
        border-radius: 10px;
        padding: 15px;
        margin: 15px 0;
    }
    
    .alert-title {
        color: #d84315;
        font-size: 15px;
        font-weight: bold;
        margin-bottom: 10px;
    }
    
    . vpn-alert {
        background-color: #e3f2fd;
        border-left: 4px solid #1976d2;
        padding: 12px;
        margin: 8px 0;
        border-radius: 6px;
        color: #0d47a1;
        font-weight: 500;
        font-size: 13px;
    }
    
    .proxy-alert {
        background-color: #ffebee;
        border-left: 4px solid #d32f2f;
        padding: 12px;
        margin: 8px 0;
        border-radius: 6px;
        color: #b71c1c;
        font-weight: 500;
        font-size: 13px;
    }
    
    . abuse-alert {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
        padding: 12px;
        margin: 8px 0;
        border-radius: 6px;
        color: #e65100;
        font-weight: 500;
        font-size: 13px;
    }
    
    .tor-alert {
        background-color: #f3e5f5;
        border-left: 4px solid #7b1fa2;
        padding: 12px;
        margin: 8px 0;
        border-radius: 6px;
        color: #4a148c;
        font-weight: 500;
        font-size: 13px;
    }
    
    .bot-alert {
        background-color: #fce4ec;
        border-left: 4px solid #c2185b;
        padding: 12px;
        margin: 8px 0;
        border-radius: 6px;
        color: #880e4f;
        font-weight: 500;
        font-size: 13px;
    }
    
    .virustotal-section {
        background: linear-gradient(135deg, #e8f1ff 0%, #f0f4ff 100%);
        border: 2px solid #2a5298;
        border-radius: 12px;
        padding: 20px;
        margin: 15px 0;
    }
    
    .virustotal-title {
        color: #1e3c72;
        font-size: 15px;
        font-weight: bold;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    .metric-highlight {
        background-color: white;
        border: 1px solid #2a5298;
        border-radius: 8px;
        padding: 12px;
        text-align: center;
        margin: 5px;
    }
    
    .metric-value-highlight {
        font-size: 24px;
        font-weight: bold;
        color: #1e3c72;
    }
    
    .metric-label-highlight {
        font-size: 11px;
        color: #2a5298;
        margin-top: 5px;
        font-weight: 600;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🔍 Análise de IP")
st.markdown("Verifique a reputação de endereços IP em múltiplas fontes de segurança")

config = load_config()

if not config.    get('virustotal_api_key'):
    st.error("❌ VirusTotal API não configurada. Acesse Configurações.")
    st.stop()

# Inicializar serviços
vt_service = VirusTotalService(config['virustotal_api_key'])
abuseipdb_service = AbuseIPDBService(config.    get('abuseipdb_api_key', '')) if config.get('abuseipdb_api_key') else None
ipinfo_service = IPInfoService(config.get('ipinfo_token', '')) if config.get('ipinfo_token') else None
shodan_service = ShodanService(config.get('shodan_api_key', '')) if config.get('shodan_api_key') else None
greynoise_service = GreyNoiseService(config.get('greynoise_api_key', '')) if config.get('greynoise_api_key') else None
ipqualityscore_service = IPQualityScoreService(config.    get('ipqualityscore_api_key', '')) if config.get('ipqualityscore_api_key') else None

# Inicializar session state
if 'analyzed_ips' not in st.  session_state:
    st.   session_state.analyzed_ips = {}

# ============================================
# SEÇÃO DE ENTRADA
# ============================================
st.markdown("## 📝 Inserir IP para Análise")

col1, col2 = st.   columns([4, 1])

with col1:
    ip_input = st.text_input(
        "Cole o IP aqui:",
        placeholder="8.8.8.8 ou 1.1.1. 1",
        key="ip_input_main"
    )

with col2:
    st.write("")
    st.write("")
    analyze_single = st.button("🔍 Analisar", key="analyze_single_btn", use_container_width=True)

# Analisar um único IP
if analyze_single and ip_input.    strip():
    ip_value = ip_input.strip()
    
    if not validate_ip(ip_value):
        st.error(f"❌ IP inválido: '{ip_value}'")
    else:
        with st.spinner(f"🔄 Analisando {ip_value}..."):
            vt_result = vt_service.analyze_ip(ip_value)
            
            combined_result = {'vt': vt_result}
            
            if abuseipdb_service:
                combined_result['abuseipdb'] = abuseipdb_service.check_ip(ip_value)
            
            if ipinfo_service:
                combined_result['ipinfo'] = ipinfo_service.    get_ip_info(ip_value)
            
            if shodan_service:
                combined_result['shodan'] = shodan_service.search_host(ip_value)
            
            if greynoise_service:
                combined_result['greynoise'] = greynoise_service.get_ip_info(ip_value)
            
            if ipqualityscore_service:
                combined_result['ipqualityscore'] = ipqualityscore_service.check_ip(ip_value)
            
            st.session_state.analyzed_ips[ip_value] = combined_result

# ============================================
# FUNÇÃO PARA RENDERIZAR RESULTADO
# ============================================

def render_ip_result(ip_value, ip_data):
    """Renderiza um resultado de análise de IP - Integrado e Limpo"""
    vt_result = ip_data.    get('vt', {})
    abuseipdb_result = ip_data.   get('abuseipdb', {})
    ipinfo_result = ip_data.get('ipinfo', {})
    shodan_result = ip_data.get('shodan', {})
    greynoise_result = ip_data.get('greynoise', {})
    ipqualityscore_result = ip_data.  get('ipqualityscore', {})
    
    # Calcular risco integrado
    is_vpn = ipqualityscore_result.get('vpn', False)
    is_proxy = ipqualityscore_result.    get('proxy', False)
    is_tor = ipqualityscore_result.get('tor', False)
    is_bot = ipqualityscore_result. get('bot_status', False)
    fraud_score = ipqualityscore_result.get('fraud_score', 0)
    reputation = vt_result.get('reputation', 0)
    abuse_score = abuseipdb_result.get('abuse_confidence_score', 0)
    recent_abuse = ipqualityscore_result.get('recent_abuse', False)
    vt_detections = vt_result.get('last_analysis_stats', {}).get('malicious', 0)
    
    # Determinar status e cor
    if is_vpn or is_proxy or is_tor:
        status_text = '⚠️ VPN/Proxy/Tor Detectado'
        risk_level = 'ALTO'
    elif reputation < -50 or abuse_score > 75 or fraud_score > 75 or vt_detections > 5:
        status_text = '🔴 Malicioso'
        risk_level = 'CRÍTICO'
    elif reputation < 0 or abuse_score > 25 or fraud_score > 50 or vt_detections > 0:
        status_text = '🟡 Suspeito'
        risk_level = 'MODERADO'
    else:
        status_text = '🟢 Seguro'
        risk_level = 'BAIXO'
    
    # Exibir header integrado
    st.markdown(f"""
        <div class="ip-container">
            <div class="ip-address">{ip_value}</div>
            <div class="risk-score">{status_text}</div>
        </div>
    """, unsafe_allow_html=True)
    
    if vt_result.get('status') != 'error':
        # ============================================
        # MÉTRICAS PRINCIPAIS - INTEGRADAS
        # ============================================
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("🎯 Risco", risk_level, delta=None)
        
        with col2:
            st.metric("⚠️ Fraude", f"{fraud_score}%", delta=None)
        
        with col3:
            st.metric("🛡️ Reputação", reputation, delta=None)
        
        with col4:
            st.metric("📊 Abuso", abuse_score if isinstance(abuse_score, int) else 0, delta=None)
        
        # ============================================
        # VIRUSTOTAL - EM DESTAQUE
        # ============================================
        st.markdown("""
            <div class="virustotal-section">
                <div class="virustotal-title">🛡️ VirusTotal - Análise de Detecção</div>
        """, unsafe_allow_html=True)
        
        vt_col1, vt_col2, vt_col3, vt_col4 = st.columns(4)
        
        with vt_col1:
            malicious = vt_result.get('last_analysis_stats', {}).get('malicious', 0)
            st.markdown(f"""
                <div class="metric-highlight">
                    <div class="metric-value-highlight">{malicious}</div>
                    <div class="metric-label-highlight">MALICIOSO</div>
                </div>
            """, unsafe_allow_html=True)
        
        with vt_col2:
            suspicious = vt_result.get('last_analysis_stats', {}).get('suspicious', 0)
            st. markdown(f"""
                <div class="metric-highlight">
                    <div class="metric-value-highlight">{suspicious}</div>
                    <div class="metric-label-highlight">SUSPEITO</div>
                </div>
            """, unsafe_allow_html=True)
        
        with vt_col3:
            undetected = vt_result. get('last_analysis_stats', {}).get('undetected', 0)
            st.markdown(f"""
                <div class="metric-highlight">
                    <div class="metric-value-highlight">{undetected}</div>
                    <div class="metric-label-highlight">UNDETECTED</div>
                </div>
            """, unsafe_allow_html=True)
        
        with vt_col4:
            harmless = vt_result.get('last_analysis_stats', {}).get('harmless', 0)
            st.markdown(f"""
                <div class="metric-highlight">
                    <div class="metric-value-highlight">{harmless}</div>
                    <div class="metric-label-highlight">HARMLESS</div>
                </div>
            """, unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # ============================================
        # AVISOS - MODERADOS
        # ============================================
        alerts = []
        
        if is_vpn:
            alerts. append(('vpn', '🛡️ VPN Detectada'))
        if is_proxy:
            alerts.  append(('proxy', '🔌 Proxy Detectado'))
        if is_tor:
            alerts.append(('tor', '🧅 Tor Detectado'))
        if recent_abuse:
            alerts.append(('abuse', '⚠️ Abuso Recente'))
        if is_bot:
            alerts.  append(('bot', '🤖 Bot Detectado'))
        if ipqualityscore_result.get('high_risk_attacks'):
            alerts.append(('abuse', '🚨 Ataques Alto Risco'))
        
        if alerts:
            st.markdown("""
                <div class="alert-section">
                    <div class="alert-title">⚠️ Alertas Detectados</div>
            """, unsafe_allow_html=True)
            
            for alert_type, alert_text in alerts:
                if alert_type == 'vpn':
                    st.markdown(f'<div class="vpn-alert">{alert_text}</div>', unsafe_allow_html=True)
                elif alert_type == 'proxy':
                    st.markdown(f'<div class="proxy-alert">{alert_text}</div>', unsafe_allow_html=True)
                elif alert_type == 'tor':
                    st.markdown(f'<div class="tor-alert">{alert_text}</div>', unsafe_allow_html=True)
                elif alert_type == 'bot':
                    st.markdown(f'<div class="bot-alert">{alert_text}</div>', unsafe_allow_html=True)
                elif alert_type == 'abuse':
                    st.markdown(f'<div class="abuse-alert">{alert_text}</div>', unsafe_allow_html=True)
            
            st.markdown("""
                </div>
            """, unsafe_allow_html=True)
        
        # ============================================
        # INFORMAÇÕES GERAIS - INTEGRADAS
        # ============================================
        st.markdown("---")
        st.markdown("### 📋 Informações Completas")
        
        # Abas para organizar melhor
        tab1, tab2, tab3 = st.tabs(["🌍 Localização", "🔗 Conexão", "🔒 Segurança"])
        
        with tab1:
            col1, col2 = st.   columns(2)
            with col1:
                st.metric("País", ipqualityscore_result.get('country', ipinfo_result.get('country_name', 'N/A')))
                st.metric("Cidade", ipqualityscore_result.get('city', ipinfo_result.   get('city', 'N/A')))
            with col2:
                st.metric("Região", ipqualityscore_result.get('region', ipinfo_result.get('region', 'N/A')))
                st.metric("CEP", ipqualityscore_result.get('zip_code', 'N/A'))
        
        with tab2:
            col1, col2 = st.   columns(2)
            with col1:
                st.metric("ISP", ipqualityscore_result.get('isp', abuseipdb_result.get('isp', 'N/A')))
                st.metric("Organização", ipqualityscore_result.get('organization', 'N/A'))
            with col2:
                st.metric("Tipo Conexão", ipqualityscore_result.get('connection_type', 'N/A'))
                st.metric("ASN", ipqualityscore_result.get('asn', 'N/A'))
        
        with tab3:
            col1, col2 = st.   columns(2)
            with col1:
                recent_abuse_text = "🚨 Sim" if recent_abuse else "✓ Não"
                st.  metric("Abuso Recente", recent_abuse_text)
                st.  metric("Abusador Frequente", "🚨 Sim" if ipqualityscore_result.get('frequent_abuser') else "✓ Não")
            with col2:
                st.   metric("Conexão Compartilhada", "Sim" if ipqualityscore_result.  get('shared_connection') else "Não")
                st.metric("Scanner Segurança", "Sim" if ipqualityscore_result.get('security_scanner') else "Não")
        
        # ============================================
        # INFORMAÇÕES ADICIONAIS (Expandível)
        # ============================================
        with st.expander("🔧 Informações Adicionais"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**AbuseIPDB**")
                st. write(f"Score: {abuseipdb_result.get('abuse_confidence_score', 'N/A')}")
                st.write(f"Reports: {abuseipdb_result.  get('total_reports', 0)}")
                st.write(f"Velocidade: {ipqualityscore_result.get('abuse_velocity', 'N/A')}")
            
            with col2:
                st.markdown("**IPQualityScore**")
                st.write(f"Fraud Score: {fraud_score}%")
                st.write(f"Tipo Conexão: {ipqualityscore_result.get('connection_type', 'N/A')}")
            
            with col3:
                st.markdown("**Shodan**")
                if shodan_result and shodan_result.get('status') == 'success':
                    ports = shodan_result. get('ports', [])
                    st.write(f"Portos: {len(ports)}")
                    if ports:
                        st.code(', '.join(map(str, ports[:10])))
                else:
                    st.write("Sem dados")

# ============================================
# SEÇÃO DE RESULTADOS
# ============================================
if st.session_state.analyzed_ips:
    st. markdown("---")
    st.markdown("## 📊 Resultados da Análise")
    
    ip_list = list(st. session_state.analyzed_ips.keys())
    
    if len(ip_list) == 1:
        ip_value = ip_list[0]
        ip_data = st.   session_state.analyzed_ips[ip_value]
        render_ip_result(ip_value, ip_data)
    else:
        tabs = st.tabs(ip_list)
        for tab, ip_value in zip(tabs, ip_list):
            with tab:
                ip_data = st.  session_state. analyzed_ips[ip_value]
                render_ip_result(ip_value, ip_data)
    
    # Botão para limpar
    st.markdown("---")
    if st.button("🗑️ Limpar Análises", use_container_width=True):
        st.session_state. analyzed_ips = {}
        st.rerun()

else:
    st.info("ℹ️ Cole um IP acima para começar a análise")