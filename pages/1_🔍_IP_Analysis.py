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
import time

# -------------------------------------------------------------------
# CONFIG STREAMLIT
# -------------------------------------------------------------------
st.set_page_config(
    page_title="Análise de IP",
    page_icon="🔍",
    layout="wide"
)

# -------------------------------------------------------------------
# CSS GLOBAL (mesmo padrão para todas as páginas)
# -------------------------------------------------------------------
st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(circle at top, #020617 0, #020617 55%);
        color: #f9fafb;  /* texto principal branco */
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    .main > div {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    /* Shell principal de cada página */
    .page-shell {
        background: #020617;
        border-radius: 18px;
        border: 1px solid rgba(148, 163, 184, 0.35);
        box-shadow: 0 20px 45px rgba(15, 23, 42, 0.85);
        padding: 1.6rem 1.4rem 1.9rem;
        margin-bottom: 1.5rem;
    }

    .page-shell-header {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        gap: 0.75rem;
        flex-wrap: wrap;
        margin-bottom: 1rem;
    }

    .page-shell-title {
        font-size: 1.6rem;
        font-weight: 650;
        letter-spacing: -0.03em;
        display: flex;
        align-items: center;
        gap: 0.6rem;
        color: #f9fafb;  /* título branco */
    }

    .page-shell-subtitle {
        color: #e5e7eb;  /* subtítulo quase branco */
        font-size: 0.9rem;
    }

    .page-shell-badge {
        font-size: 0.68rem;
        padding: 0.2rem 0.7rem;
        border-radius: 999px;
        border: 1px solid rgba(148, 163, 184, 0.6);
        background: rgba(15, 23, 42, 0.96);
        color: #e5e7eb;
        text-transform: uppercase;
        letter-spacing: 0.15em;
    }

    /* Cards genéricos */
    .card-row {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 0.85rem;
        margin-top: 1.1rem;
    }

    .card {
        background: #020617;
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.5);
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.9);
        padding: 0.9rem 1rem;
    }

    .card-muted {
        background: #020617;
        border-radius: 14px;
        border: 1px dashed rgba(148, 163, 184, 0.45);
        box-shadow: none;
        padding: 0.9rem 1rem;
    }

    .card-label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.16em;
        color: #cbd5f5;  /* label clara */
        margin-bottom: 0.3rem;
    }

    .card-value {
        font-size: 1.35rem;
        font-weight: 650;
        color: #ffffff;  /* valor branco */
    }

    .card-sub {
        font-size: 0.8rem;
        color: #e5e7eb;  /* subtítulo claro */
        margin-top: 0.25rem;
    }

    /* Status e badges */
    .status-ok   { color: #22c55e; }
    .status-warn { color: #facc15; }
    .status-bad  { color: #fca5a5; }

    .badge-soft {
        font-size: 0.72rem;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        background: rgba(15,23,42,0.96);
        border: 1px solid rgba(148,163,184,0.5);
        color: #e5e7eb;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        margin-top: 0.35rem;
    }

    /* Input IP */
    .ip-input-label {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        color: #cbd5f5;
        margin-bottom: 0.25rem;
    }

    .ip-helper {
        font-size: 0.78rem;
        color: #9ca3af;
        margin-top: 0.25rem;
    }

    /* Alertas detectados – maiores, com texto branco */
    .alert-section {
        background: #111827;
        border-radius: 16px;
        border: 1px solid rgba(248, 250, 252, 0.08);
        padding: 1.15rem 1.15rem;
        margin-top: 1.25rem;
    }

    .alert-title {
        font-size: 0.95rem;
        font-weight: 600;
        color: #fdba74;
        display: flex;
        align-items: center;
        gap: 0.4rem;
        margin-bottom: 0.7rem;
    }

    .alert-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 0.55rem;
    }

    .pill-alert {
        font-size: 0.86rem;              /* maior */
        border-radius: 999px;
        padding: 0.45rem 1rem;           /* mais alto e mais largo */
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        border: 1px solid rgba(148, 163, 184, 0.55);
        background: #1d2a3f;
        color: #ffffff;                  /* texto branco */
        font-weight: 500;
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.75);
    }

    .pill-vpn {
        border-color: rgba(59,130,246,0.9);
        background: linear-gradient(135deg, #2563eb, #1e293b);
        color: #ffffff;
    }

    .pill-proxy {
        border-color: rgba(14,165,233,0.9);
        background: linear-gradient(135deg, #0284c7, #1e293b);
        color: #ffffff;
    }

    .pill-tor {
        border-color: rgba(124,58,237,0.9);
        background: linear-gradient(135deg, #7c3aed, #1e293b);
        color: #ffffff;
    }

    .pill-bot {
        border-color: rgba(244,114,182,0.9);
        background: linear-gradient(135deg, #db2777, #1e293b);
        color: #ffffff;
    }

    .pill-abuse {
        border-color: rgba(239,68,68,0.95);
        background: linear-gradient(135deg, #ef4444, #1e293b);
        color: #ffffff;
    }

    .block-section-title {
        margin-top: 1.3rem;
        font-size: 1rem;
        font-weight: 600;
        color: #f9fafb;
    }

    /* Histórico simples */
    .history-badge {
        font-size: 0.8rem;
        border-radius: 999px;
        padding: 0.25rem 0.7rem;
        border: 1px solid rgba(148,163,184,0.4);
        background: #020617;
        color: #e5e7eb;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        margin-right: 0.35rem;
        margin-bottom: 0.25rem;
    }

    /* Botões secundários (limpar, etc.) */
    .stButton>button[kind="secondary"] {
        border-radius: 999px !important;
        background: transparent !important;
        border: 1px solid rgba(148,163,184,0.5) !important;
        color: #e5e7eb !important;
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
# HEADER / SHELL DA PÁGINA
# -------------------------------------------------------------------
st.markdown(
    """
    <div class="page-shell">
      <div class="page-shell-header">
        <div>
          <div class="page-shell-title">
            🔍 Análise de IP
          </div>
          <div class="page-shell-subtitle">
            Verifique reputação, localização, exposição e sinais de abuso de endereços IP em múltiplas fontes.
          </div>
        </div>
        <span class="page-shell-badge">Threat Intelligence • IP</span>
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
    st.write("")
    st.write("")
    analyze_single = st.button("🔍 Analisar IP", key="analyze_single_btn", use_container_width=True)

st.markdown("</div>", unsafe_allow_html=True)  # fecha .page-shell

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
# FUNÇÃO DE RENDERIZAÇÃO
# -------------------------------------------------------------------
def render_ip_result(ip_value, ip_data):
    vt_result = ip_data.get("vt", {})
    abuseipdb_result = ip_data.get("abuseipdb", {})
    ipinfo_result = ip_data.get("ipinfo", {})
    shodan_result = ip_data.get("shodan", {})
    greynoise_result = ip_data.get("greynoise", {})
    ipqualityscore_result = ip_data.get("ipqualityscore", {})

    is_vpn = ipqualityscore_result.get("vpn", False)
    is_proxy = ipqualityscore_result.get("proxy", False)
    is_tor = ipqualityscore_result.get("tor", False)
    is_bot = ipqualityscore_result.get("bot_status", False)
    fraud_score = ipqualityscore_result.get("fraud_score", 0)

    # AbuseIPDB pode usar chaves diferentes conforme sua implementação;
    # se na sua resposta a chave for 'abuse_confidence_score', ajuste aqui.
    abuse_score = abuseipdb_result.get("abuse_confidence_score", 0)
    recent_abuse = bool(abuseipdb_result.get("total_reports", 0))

    reputation = vt_result.get("reputation", 0)

    # Risk score integrado simples
    risk_score = max(
        fraud_score,
        abuse_score if isinstance(abuse_score, (int, float)) else 0,
        100 if is_tor or is_bot else 0,
    )

    if risk_score >= 80:
        status_text = "Alto Risco"
        status_class = "status-bad"
    elif risk_score >= 40:
        status_text = "Risco Moderado"
        status_class = "status-warn"
    else:
        status_text = "Baixo Risco"
        status_class = "status-ok"

    st.markdown(f"### 📌 Resultado para **`{ip_value}`**")

    # CARDS PRINCIPAIS
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="card">
                <div class="card-label">Score Integrado</div>
                <div class="card-value {status_class}">{risk_score}</div>
                <div class="card-sub">{status_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="card">
                <div class="card-label">Reputação (VirusTotal)</div>
                <div class="card-value">{reputation}</div>
                <div class="card-sub">Indicador bruto de reputação</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        abuse_val = abuse_score if isinstance(abuse_score, (int, float)) else 0
        st.markdown(
            f"""
            <div class="card">
                <div class="card-label">Abuso (AbuseIPDB)</div>
                <div class="card-value">{abuse_val}</div>
                <div class="card-sub">Abuse Confidence Score</div>
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
            <div class="card card-muted">
                <div class="card-label">Localização</div>
                <div class="card-value">{country}</div>
                <div class="card-sub">Cidade: {city}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ALERTAS INTEGRADOS
    alerts = []
    if is_vpn:
        alerts.append(("vpn", "VPN Detectada"))
    if is_proxy:
        alerts.append(("proxy", "Proxy Detectado"))
    if is_tor:
        alerts.append(("tor", "Tráfego Tor Detectado"))
    if is_bot:
        alerts.append(("bot", "Possível Bot/Script"))
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

    # VIRUSTOTAL – RESUMO
    st.markdown("#### 🛡️ VirusTotal — Estatísticas de Detecção")
    stats = vt_result.get("last_analysis_stats", {})
    col_v1, col_v2, col_v3, col_v4 = st.columns(4)
    col_v1.metric("Malicious", stats.get("malicious", 0))
    col_v2.metric("Suspicious", stats.get("suspicious", 0))
    col_v3.metric("Undetected", stats.get("undetected", 0))
    col_v4.metric("Harmless", stats.get("harmless", 0))

    # DETALHES ORGANIZADOS EM ABAS
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

        if shodan_result:
            st.markdown("---")
            st.markdown("#### Shodan — Visão Geral")
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
        st.markdown("##### Dados Brutos (AbuseIPDB / IPQualityScore)")
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