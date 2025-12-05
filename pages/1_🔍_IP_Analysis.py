import streamlit as st
import pandas as pd
from config.settings import load_config
from services.virustotal import VirusTotalService
from services.abuseipdb import AbuseIPDBService
from services.ipinfo import IPInfoService
from services.shodan import ShodanService
from services.greynoise import GreyNoiseService
from services.ipqualityscore import IPQualityScoreService
from utils.validators import validate_ip
from utils.parsers import TextParser
from utils.formatters import ResultFormatter
import time

# -------------------------------------------------------------------
# CONFIG STREAMLIT + NOVO TEMA VISUAL
# -------------------------------------------------------------------
st.set_page_config(
    page_title="Análise de IP",
    page_icon="🔍",
    layout="wide"
)

# CSS redesenhado – layout dark, cards limpos e foco em métricas
st.markdown(
    """
    <style>
    /* Background geral */
    .stApp {
        background: radial-gradient(circle at top, #0f172a 0, #020617 55%);
        color: #e5e7eb;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    /* Ajuste de padding da área principal */
    .main > div {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    /* Títulos */
    h1, h2, h3, h4 {
        color: #e5e7eb !important;
    }

    /* Container principal do IP */
    .ip-shell {
        background: rgba(15, 23, 42, 0.92);
        border-radius: 20px;
        border: 1px solid rgba(148, 163, 184, 0.25);
        box-shadow: 0 20px 45px rgba(15, 23, 42, 0.9);
        padding: 1.5rem 1.5rem 1.8rem;
        margin-bottom: 1.5rem;
    }

    .ip-shell-header {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        gap: 0.75rem;
        flex-wrap: wrap;
        margin-bottom: 1rem;
    }

    .ip-shell-title {
        font-size: 1.6rem;
        font-weight: 650;
        letter-spacing: -0.03em;
        display: flex;
        align-items: center;
        gap: 0.6rem;
    }

    .ip-shell-subtitle {
        color: #9ca3af;
        font-size: 0.9rem;
    }

    .ip-badge {
        font-size: 0.68rem;
        padding: 0.2rem 0.7rem;
        border-radius: 999px;
        border: 1px solid rgba(148, 163, 184, 0.5);
        background: rgba(15, 23, 42, 0.86);
        color: #9ca3af;
        text-transform: uppercase;
        letter-spacing: 0.15em;
    }

    /* Campo de IP */
    .ip-input-label {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        color: #9ca3af;
        margin-bottom: 0.25rem;
    }

    .ip-helper {
        font-size: 0.78rem;
        color: #6b7280;
        margin-top: 0.25rem;
    }

    /* Containers de cards */
    .card-row {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 0.75rem;
        margin-top: 1.1rem;
    }

    .card-metric {
        background: radial-gradient(circle at top left, rgba(59,130,246,0.22), rgba(15,23,42,1));
        border-radius: 16px;
        border: 1px solid rgba(37, 99, 235, 0.35);
        padding: 0.9rem 1rem;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.85);
    }

    .card-metric-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.16em;
        color: #9ca3af;
        margin-bottom: 0.35rem;
    }

    .card-metric-value {
        font-size: 1.4rem;
        font-weight: 650;
        letter-spacing: 0.02em;
    }

    .badge-soft {
        font-size: 0.7rem;
        padding: 0.15rem 0.5rem;
        border-radius: 999px;
        background: rgba(15,23,42,0.9);
        border: 1px solid rgba(148,163,184,0.4);
        color: #9ca3af;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        margin-top: 0.35rem;
    }

    .status-ok   { color: #22c55e; }
    .status-warn { color: #facc15; }
    .status-bad  { color: #ef4444; }

    /* Bloco de alertas integrados */
    .alert-section {
        background: rgba(24, 24, 27, 0.98);
        border-radius: 16px;
        border: 1px solid rgba(248, 250, 252, 0.08);
        padding: 0.95rem 1rem;
        margin-top: 1.25rem;
    }

    .alert-title {
        font-size: 0.9rem;
        font-weight: 600;
        color: #f97316;
        display: flex;
        align-items: center;
        gap: 0.4rem;
        margin-bottom: 0.55rem;
    }

    .alert-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 0.4rem;
    }

    .pill-alert {
        font-size: 0.75rem;
        border-radius: 999px;
        padding: 0.25rem 0.7rem;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        border: 1px solid rgba(148, 163, 184, 0.45);
        background: rgba(15, 23, 42, 0.92);
        color: #e5e7eb;
    }

    .pill-vpn     { border-color: rgba(59,130,246,0.6);   color:#bfdbfe; }
    .pill-proxy   { border-color: rgba(14,165,233,0.6);   color:#e0f2fe; }
    .pill-tor     { border-color: rgba(124,58,237,0.7);   color:#e9d5ff; }
    .pill-bot     { border-color: rgba(244,114,182,0.7);  color:#fce7f3; }
    .pill-abuse   { border-color: rgba(239,68,68,0.7);    color:#fee2e2; }

    /* Seção VirusTotal em destaque */
    .virustotal-section {
        margin-top: 1.4rem;
        background: linear-gradient(135deg, rgba(30,64,175,0.35), rgba(15,23,42,0.98));
        border-radius: 18px;
        border: 1px solid rgba(37,99,235,0.5);
        padding: 1rem 1.1rem 1.1rem;
        box-shadow: 0 18px 40px rgba(15, 23, 42, 0.95);
    }

    .virustotal-title {
        font-size: 0.9rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #dbeafe;
        margin-bottom: 0.7rem;
        display: flex;
        align-items: center;
        gap: 0.4rem;
    }

    .metric-highlight {
        background: rgba(15,23,42,0.95);
        border-radius: 0.9rem;
        border: 1px solid rgba(148, 163, 184, 0.4);
        padding: 0.65rem 0.75rem;
        text-align: center;
        box-shadow: 0 10px 25px rgba(15, 23, 42, 0.85);
    }

    .metric-value-highlight {
        font-size: 1.35rem;
        font-weight: 650;
        margin-bottom: 0.05rem;
    }

    .metric-label-highlight {
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 0.14em;
        color: #9ca3af;
    }

    /* Tabs de detalhes */
    .block-section-title {
        margin-top: 1.4rem;
        font-size: 1rem;
        font-weight: 600;
    }

    /* Historico de IPs */
    .history-badge {
        font-size: 0.8rem;
        border-radius: 999px;
        padding: 0.25rem 0.7rem;
        border: 1px solid rgba(148,163,184,0.4);
        background: rgba(15,23,42,0.9);
        color: #9ca3af;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        margin-right: 0.35rem;
        margin-bottom: 0.25rem;
    }

    /* Botão limpar análises – melhor destaque */
    .stButton>button[kind="secondary"] {
        border-radius: 999px !important;
        background: transparent !important;
        border: 1px solid rgba(148,163,184,0.5) !important;
        color: #9ca3af !important;
        font-size: 0.85rem !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -------------------------------------------------------------------
# CARREGAR CONFIG E SERVIÇOS
# -------------------------------------------------------------------
config = load_config()

if not config.get("virustotal_api_key"):
    st.error("❌ VirusTotal API não configurada. Acesse Configurações.")
    st.stop()

vt_service = VirusTotalService(config["virustotal_api_key"])
abuseipdb_service = AbuseIPDBService(config["abuseipdb_api_key"]) if config.get("abuseipdb_api_key") else None
ipinfo_service = IPInfoService(config["ipinfo_token"]) if config.get("ipinfo_token") else None
shodan_service = ShodanService(config["shodan_api_key"]) if config.get("shodan_api_key") else None
greynoise_service = GreyNoiseService(config["greynoise_api_key"]) if config.get("greynoise_api_key") else None
ipqualityscore_service = IPQualityScoreService(config["ipqualityscore_api_key"]) if config.get("ipqualityscore_api_key") else None

# -------------------------------------------------------------------
# HEADER DA PÁGINA
# -------------------------------------------------------------------
st.markdown(
    """
    <div class="ip-shell">
      <div class="ip-shell-header">
        <div>
          <div class="ip-shell-title">
            🔍 Análise de IP
            <span class="ip-badge">Threat Intelligence • Multi‑Fonte</span>
          </div>
          <div class="ip-shell-subtitle">
            Consulte reputação, localização, exposição e sinais de abuso de endereços IP em múltiplas fontes.
          </div>
        </div>
      </div>
    """,
    unsafe_allow_html=True,
)

# -------------------------------------------------------------------
# INPUT PRINCIPAL
# -------------------------------------------------------------------
col_input, col_button = st.columns([4, 1])

with col_input:
    st.markdown('<div class="ip-input-label">Endereço IP</div>', unsafe_allow_html=True)
    ip_input = st.text_input(
        label="",
        placeholder="Ex.: 8.8.8.8 ou 1.1.1.1",
        key="ip_input_main",
    )
    st.markdown(
        '<div class="ip-helper">Cole um único IP para análise detalhada. Resultados de múltiplas fontes serão consolidados abaixo.</div>',
        unsafe_allow_html=True,
    )

with col_button:
    st.write("")  # espaço
    st.write("")
    analyze_single = st.button("🔍 Analisar IP", key="analyze_single_btn", use_container_width=True)

st.markdown("</div>", unsafe_allow_html=True)  # fecha .ip-shell

# -------------------------------------------------------------------
# SESSION STATE
# -------------------------------------------------------------------
if "analyzed_ips" not in st.session_state:
    st.session_state.analyzed_ips = {}

# -------------------------------------------------------------------
# EXECUTAR ANÁLISE
# -------------------------------------------------------------------
if analyze_single and ip_input.strip():
    ip_value = ip_input.strip()

    if not validate_ip(ip_value):
        st.error(f"❌ IP inválido: '{ip_value}'")
    else:
        with st.spinner(f"🔄 Analisando {ip_value}..."):
            vt_result = vt_service.analyze_ip(ip_value)
            combined_result = {"vt": vt_result}

            if abuseipdb_service:
                combined_result["abuseipdb"] = abuseipdb_service.check_ip(ip_value)
            if ipinfo_service:
                combined_result["ipinfo"] = ipinfo_service.get_ip_info(ip_value)
            if shodan_service:
                combined_result["shodan"] = shodan_service.search_host(ip_value)
            if greynoise_service:
                combined_result["greynoise"] = greynoise_service.get_ip_info(ip_value)
            if ipqualityscore_service:
                combined_result["ipqualityscore"] = ipqualityscore_service.check_ip(ip_value)

            st.session_state.analyzed_ips[ip_value] = combined_result

# -------------------------------------------------------------------
# FUNÇÃO DE RENDERIZAÇÃO – NOVO DESIGN
# -------------------------------------------------------------------
def render_ip_result(ip_value, ip_data):
    """Renderiza um resultado de análise de IP com layout redesenhado."""

    vt_result = ip_data.get("vt", {})
    abuseipdb_result = ip_data.get("abuseipdb", {})
    ipinfo_result = ip_data.get("ipinfo", {})
    shodan_result = ip_data.get("shodan", {})
    greynoise_result = ip_data.get("greynoise", {})
    ipqualityscore_result = ip_data.get("ipqualityscore", {})

    # Cálculo de métricas integradas básicas
    is_vpn = ipqualityscore_result.get("vpn", False)
    is_proxy = ipqualityscore_result.get("proxy", False)
    is_tor = ipqualityscore_result.get("tor", False)
    is_bot = ipqualityscore_result.get("bot_status", False)
    fraud_score = ipqualityscore_result.get("fraud_score", 0)
    reputation = vt_result.get("reputation", 0)
    abuse_score = abuseipdb_result.get("abuseConfidenceScore", 0)
    recent_abuse = abuseipdb_result.get("totalReports", 0) > 0

    # Score geral simplificado
    # você pode ajustar a fórmula conforme sua lógica
    risk_score = max(
        fraud_score,
        abuse_score if isinstance(abuse_score, int) else 0,
        100 if is_tor or is_bot else 0,
    )

    # Texto e cor de status
    if risk_score >= 80:
        status_text = "Alto Risco"
        status_class = "status-bad"
    elif risk_score >= 40:
        status_text = "Risco Moderado"
        status_class = "status-warn"
    else:
        status_text = "Baixo Risco"
        status_class = "status-ok"

    # ---------------------------------------------------------------
    # CABEÇALHO DO RESULTADO
    # ---------------------------------------------------------------
    st.markdown(f"### 📌 Resultado para **`{ip_value}`**")

    # Linha de cards principais
    st.markdown(
        """
        <div class="card-row">
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="card-metric">
                <div class="card-metric-label">Score Integrado</div>
                <div class="card-metric-value {status_class}">{risk_score}</div>
                <div class="badge-soft"><span class="{status_class}">●</span>{status_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="card-metric">
                <div class="card-metric-label">Reputação (VirusTotal)</div>
                <div class="card-metric-value">{reputation}</div>
                <div class="badge-soft">Fonte: VirusTotal</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        abuse_val = abuse_score if isinstance(abuse_score, int) else 0
        st.markdown(
            f"""
            <div class="card-metric">
                <div class="card-metric-label">Abuso (AbuseIPDB)</div>
                <div class="card-metric-value">{abuse_val}</div>
                <div class="badge-soft">Confidence Score</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        country = ipqualityscore_result.get(
            "country", ipinfo_result.get("country_name", "N/A")
        )
        city = ipqualityscore_result.get("city", ipinfo_result.get("city", "N/A"))
        st.markdown(
            f"""
            <div class="card-metric">
                <div class="card-metric-label">Localização</div>
                <div class="card-metric-value">{country}</div>
                <div class="badge-soft">Cidade: {city}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # ---------------------------------------------------------------
    # ALERTAS INTEGRADOS
    # ---------------------------------------------------------------
    alerts = []
    if is_vpn:
        alerts.append(("vpn", "VPN Detectada"))
    if is_proxy:
        alerts.append(("proxy", "Proxy Detectado"))
    if is_tor:
        alerts.append(("tor", "Tráfego Tor Detectado"))
    if is_bot:
        alerts.append(("bot", "Possível Bot/SCRIPT Automático"))
    if ipqualityscore_result.get("high_risk_attacks"):
        alerts.append(("abuse", "Ataques de Alto Risco Detectados"))
    if recent_abuse:
        alerts.append(("abuse", "Relatos Recentes de Abuso (AbuseIPDB)"))

    if alerts:
        st.markdown(
            """
            <div class="alert-section">
                <div class="alert-title">⚠️ Alertas Detectados</div>
                <div class="alert-grid">
            """,
            unsafe_allow_html=True,
        )

        for alert_type, text in alerts:
            pill_class = {
                "vpn": "pill-vpn",
                "proxy": "pill-proxy",
                "tor": "pill-tor",
                "bot": "pill-bot",
                "abuse": "pill-abuse",
            }.get(alert_type, "")

            st.markdown(
                f"""<span class="pill-alert {pill_class}">● {text}</span>""",
                unsafe_allow_html=True,
            )

        st.markdown("</div></div>", unsafe_allow_html=True)

    # ---------------------------------------------------------------
    # VIRUSTOTAL EM DESTAQUE
    # ---------------------------------------------------------------
    st.markdown(
        """
        <div class="virustotal-section">
            <div class="virustotal-title">🛡️ VirusTotal — Análise de Detecção</div>
        """,
        unsafe_allow_html=True,
    )

    vt_col1, vt_col2, vt_col3, vt_col4 = st.columns(4)

    with vt_col1:
        malicious = vt_result.get("last_analysis_stats", {}).get("malicious", 0)
        st.markdown(
            f"""
            <div class="metric-highlight">
                <div class="metric-value-highlight status-bad">{malicious}</div>
                <div class="metric-label-highlight">Malicioso</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with vt_col2:
        suspicious = vt_result.get("last_analysis_stats", {}).get("suspicious", 0)
        st.markdown(
            f"""
            <div class="metric-highlight">
                <div class="metric-value-highlight status-warn">{suspicious}</div>
                <div class="metric-label-highlight">Suspeito</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with vt_col3:
        undetected = vt_result.get("last_analysis_stats", {}).get("undetected", 0)
        st.markdown(
            f"""
            <div class="metric-highlight">
                <div class="metric-value-highlight">{undetected}</div>
                <div class="metric-label-highlight">Undetected</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with vt_col4:
        harmless = vt_result.get("last_analysis_stats", {}).get("harmless", 0)
        st.markdown(
            f"""
            <div class="metric-highlight">
                <div class="metric-value-highlight status-ok">{harmless}</div>
                <div class="metric-label-highlight">Harmless</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # ---------------------------------------------------------------
    # DETALHES ORGANIZADOS EM ABAS
    # ---------------------------------------------------------------
    st.markdown("### 📋 Informações detalhadas")

    tab1, tab2, tab3 = st.tabs(["🌍 Localização", "🔗 Conexão / Infra", "🔒 Segurança & Abuso"])

    with tab1:
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric(
                "País",
                ipqualityscore_result.get("country", ipinfo_result.get("country_name", "N/A")),
            )
            st.metric(
                "Cidade",
                ipqualityscore_result.get("city", ipinfo_result.get("city", "N/A")),
            )
        with col_b:
            st.metric(
                "Região",
                ipqualityscore_result.get("region", ipinfo_result.get("region", "N/A")),
            )
            st.metric("CEP", ipqualityscore_result.get("zip_code", "N/A"))

    with tab2:
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric(
                "ISP",
                ipqualityscore_result.get("isp", abuseipdb_result.get("isp", "N/A")),
            )
            st.metric("Organização", ipqualityscore_result.get("organization", "N/A"))
        with col_b:
            st.metric("Tipo de Conexão", ipqualityscore_result.get("connection_type", "N/A"))
            st.metric("ASN", ipqualityscore_result.get("asn", "N/A"))

        # se quiser, você pode adicionar detalhes de Shodan/GreyNoise aqui
        if shodan_result:
            st.markdown("---")
            st.markdown("#### Shodan — Portas e Serviços")
            # Exemplo simples; adapte ao formato real do retorno
            st.json(shodan_result)

    with tab3:
        col_a, col_b = st.columns(2)
        with col_a:
            recent_abuse_text = "🚨 Sim" if recent_abuse else "✓ Não"
            st.metric("Abuso Recente", recent_abuse_text)
            st.metric(
                "Abusador Frequente",
                "🚨 Sim" if ipqualityscore_result.get("frequent_abuser") else "✓ Não",
            )
        with col_b:
            st.metric("Fraud Score", fraud_score)
            st.metric(
                "Alto Risco",
                "🚨 Sim" if ipqualityscore_result.get("high_risk_attacks") else "✓ Não",
            )

        st.markdown("---")
        st.markdown("##### Detalhes Brutos (AbuseIPDB / IPQualityScore)")
        st.json(
            {
                "abuseipdb": abuseipdb_result,
                "ipqualityscore": ipqualityscore_result,
            }
        )

# -------------------------------------------------------------------
# SEÇÃO DE RESULTADOS / HISTÓRICO
# -------------------------------------------------------------------
if st.session_state.analyzed_ips:
    st.markdown("---")
    st.markdown("## 📊 Resultados da análise")

    ip_list = list(st.session_state.analyzed_ips.keys())

    # Histórico rápido de IPs analisados
    st.markdown("#### Histórico desta sessão")
    hist_html = "".join(
        f'<span class="history-badge">● {ip}</span>' for ip in ip_list
    )
    st.markdown(hist_html, unsafe_allow_html=True)

    st.markdown("")
    if len(ip_list) == 1:
        ip_value = ip_list[0]
        ip_data = st.session_state.analyzed_ips[ip_value]
        render_ip_result(ip_value, ip_data)
    else:
        tabs = st.tabs(ip_list)
        for tab, ip_value in zip(tabs, ip_list):
            with tab:
                ip_data = st.session_state.analyzed_ips[ip_value]
                render_ip_result(ip_value, ip_data)

    st.markdown("---")
    if st.button("🗑️ Limpar análises", type="secondary", use_container_width=True):
        st.session_state.analyzed_ips = {}
        st.rerun()
else:
    st.info("ℹ️ Cole um IP acima para começar a análise.")