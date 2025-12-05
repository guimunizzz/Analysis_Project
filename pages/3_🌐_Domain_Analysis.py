import streamlit as st
import pandas as pd
from config.settings import load_config
from services.virustotal import VirusTotalService
from utils.parsers import TextParser
from utils.formatters import ResultFormatter
from styles.theme import get_common_styles, get_sidebar_logo_html
import time

st.set_page_config(page_title="Análise de Domínio", page_icon="🌐", layout="wide")

# Apply common styles from theme
st.markdown(get_common_styles(), unsafe_allow_html=True)

# Additional styles specific to Domain Analysis page
st.markdown("""
    <style>
    /* Domain results cards */
    .domain-result-card {
        background: #020617;
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.5);
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.9);
        padding: 1.2rem;
        margin-bottom: 1rem;
    }
    
    .domain-result-card.malicious {
        border-color: rgba(239, 68, 68, 0.7);
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.05), #020617);
    }
    
    .domain-result-card.suspicious {
        border-color: rgba(249, 115, 22, 0.7);
        background: linear-gradient(135deg, rgba(249, 115, 22, 0.05), #020617);
    }
    
    .domain-result-card.clean {
        border-color: rgba(34, 197, 94, 0.7);
        background: linear-gradient(135deg, rgba(34, 197, 94, 0.05), #020617);
    }
    
    .domain-header {
        font-size: 1.2rem;
        font-weight: 600;
        color: #f9fafb;
        margin-bottom: 0.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .domain-status-badge {
        font-size: 0.75rem;
        padding: 0.25rem 0.6rem;
        border-radius: 999px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .status-malicious {
        background: rgba(239, 68, 68, 0.2);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.5);
    }
    
    .status-suspicious {
        background: rgba(249, 115, 22, 0.2);
        color: #fdba74;
        border: 1px solid rgba(249, 115, 22, 0.5);
    }
    
    .status-clean {
        background: rgba(34, 197, 94, 0.2);
        color: #86efac;
        border: 1px solid rgba(34, 197, 94, 0.5);
    }
    
    .category-pill {
        display: inline-block;
        padding: 0.3rem 0.7rem;
        margin: 0.2rem;
        border-radius: 999px;
        font-size: 0.75rem;
        background: rgba(59, 130, 246, 0.15);
        color: #93c5fd;
        border: 1px solid rgba(59, 130, 246, 0.3);
    }
    </style>
""", unsafe_allow_html=True)

# Add sidebar logo
with st.sidebar:
    st.markdown(get_sidebar_logo_html(), unsafe_allow_html=True)

# Page header with consistent design
st.markdown("""
    <div class="page-shell">
      <div class="page-shell-header">
        <div>
          <div class="page-shell-title">
            🌐 Análise de Domínio
          </div>
          <div class="page-shell-subtitle">
            Verifique a reputação de domínios e URLs em múltiplas fontes com resultados em tempo real
          </div>
        </div>
        <span class="page-shell-badge">Threat Intelligence • Domain</span>
      </div>
    </div>
""", unsafe_allow_html=True)

config = load_config()

if not config.get('virustotal_api_key'):
    st.error("❌ VirusTotal API não configurada. Acesse Configurações.")
    st.stop()

vt_service = VirusTotalService(config['virustotal_api_key'])

# Inicializar session state
if 'analyzed_domains' not in st.session_state:
    st.session_state.analyzed_domains = {}

# ============================================
# SEÇÃO DE ENTRADA - INLINE RESULTS
# ============================================
col1, col2 = st.columns([4, 1])

with col1:
    st.markdown('<div class="ip-input-label">Domínio ou URL</div>', unsafe_allow_html=True)
    domain_input = st.text_input(
        label="",
        placeholder="Ex.: example.com ou https://malicious-site.net",
        key="domain_input_main"
    )
    st.markdown('<div class="ip-helper">Cole um domínio ou URL para análise em tempo real. Os resultados aparecerão instantaneamente abaixo.</div>', unsafe_allow_html=True)

with col2:
    st.write("")
    st.write("")
    analyze_btn = st.button("🔍 Analisar", key="analyze_domain_btn", use_container_width=True)

# Analisar domínio
if analyze_btn and domain_input.strip():
    domain_value = domain_input.strip()
    
    # Parse domain/URL
    parsed_domains = TextParser.parse_domains(domain_value)
    parsed_urls = TextParser.parse_urls(domain_value)
    
    # Extract domain from URL if necessary
    if parsed_urls and not parsed_domains:
        # Extract domain from URL
        domain_value = parsed_urls[0].split('/')[2] if '/' in parsed_urls[0] else parsed_urls[0]
    elif parsed_domains:
        domain_value = parsed_domains[0]
    
    if domain_value:
        with st.spinner(f"🔄 Analisando {domain_value}..."):
            vt_result = vt_service.analyze_domain(domain_value)
            st.session_state.analyzed_domains[domain_value] = vt_result

# ============================================
# UPLOAD EM LOTE
# ============================================
st.markdown("---")
st.markdown("### 📤 Análise em Lote")

with st.expander("📦 Carregar múltiplos domínios"):
    uploaded_file = st.file_uploader("Selecione um arquivo txt ou csv:", type=['txt', 'csv'])
    
    if uploaded_file and st.button("📤 Processar Arquivo", key="process_file_domain"):
        content = uploaded_file.read().decode('utf-8')
        domains = TextParser.parse_domains(content)
        urls = TextParser.parse_urls(content)
        
        all_targets = list(set(domains + [u.split('/')[2] if '/' in u else u for u in urls]))
        
        if all_targets:
            st.success(f"✅ {len(all_targets)} domínio(s) válido(s) encontrado(s). Iniciando análise...")
            
            progress_bar = st.progress(0)
            status_placeholder = st.empty()
            
            for idx, domain in enumerate(all_targets):
                status_placeholder.text(f"Analisando {idx + 1}/{len(all_targets)}: {domain}")
                
                vt_result = vt_service.analyze_domain(domain)
                st.session_state.analyzed_domains[domain] = vt_result
                
                progress_bar.progress((idx + 1) / len(all_targets))
                time.sleep(0.1)
            
            progress_bar.empty()
            status_placeholder.empty()
            st.success(f"✅ Análise de {len(all_targets)} domínio(s) concluída!")
        else:
            st.error("❌ Nenhum domínio válido encontrado no arquivo")

# ============================================
# FUNÇÃO PARA RENDERIZAR RESULTADO
# ============================================
def render_domain_result(domain, result):
    """Renderiza resultado de análise de domínio com design melhorado"""
    
    malicious_count = result.get('malicious_count', 0)
    suspicious_count = result.get('suspicious_count', 0)
    reputation = result.get('reputation', 0)
    categories = result.get('categories', {})
    
    # Determinar status
    if malicious_count > 0:
        status = 'malicious'
        status_text = 'Malicioso'
        status_icon = '🔴'
        status_class = 'status-malicious'
    elif suspicious_count > 0:
        status = 'suspicious'
        status_text = 'Suspeito'
        status_icon = '🟡'
        status_class = 'status-suspicious'
    else:
        status = 'clean'
        status_text = 'Limpo'
        status_icon = '🟢'
        status_class = 'status-clean'
    
    # Renderizar card
    st.markdown(f"""
        <div class="domain-result-card {status}">
            <div class="domain-header">
                {status_icon} {domain}
                <span class="domain-status-badge {status_class}">{status_text}</span>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Métricas em cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
            <div class="card">
                <div class="card-label">Detecções Maliciosas</div>
                <div class="card-value status-bad">{malicious_count}</div>
                <div class="card-sub">Vendors maliciosos</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
            <div class="card">
                <div class="card-label">Detecções Suspeitas</div>
                <div class="card-value status-warn">{suspicious_count}</div>
                <div class="card-sub">Vendors suspeitos</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col3:
        total_detections = malicious_count + suspicious_count
        st.markdown(f"""
            <div class="card">
                <div class="card-label">Total de Detecções</div>
                <div class="card-value">{total_detections}</div>
                <div class="card-sub">Detecções combinadas</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
            <div class="card card-muted">
                <div class="card-label">Reputação</div>
                <div class="card-value">{reputation}</div>
                <div class="card-sub">Score de reputação</div>
            </div>
        """, unsafe_allow_html=True)
    
    # Categorias (se houver)
    if categories:
        st.markdown("### 🏷️ Categorias Detectadas")
        category_html = ""
        for cat, value in categories.items():
            category_html += f'<span class="category-pill">{cat}: {value}</span>'
        st.markdown(category_html, unsafe_allow_html=True)
    
    # Detalhes expandíveis
    with st.expander("📋 Ver Detalhes Completos"):
        st.json(result)

# ============================================
# SEÇÃO DE RESULTADOS
# ============================================
if st.session_state.analyzed_domains:
    st.markdown("---")
    st.markdown("## 📊 Resultados da Análise")
    
    domain_list = list(st.session_state.analyzed_domains.keys())
    
    # Estatísticas gerais
    st.markdown("### 📈 Resumo Geral")
    
    total_domains = len(domain_list)
    malicious_domains = sum(1 for d in domain_list if st.session_state.analyzed_domains[d].get('malicious_count', 0) > 0)
    suspicious_domains = sum(1 for d in domain_list if st.session_state.analyzed_domains[d].get('suspicious_count', 0) > 0 and st.session_state.analyzed_domains[d].get('malicious_count', 0) == 0)
    clean_domains = total_domains - malicious_domains - suspicious_domains
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
            <div class="card">
                <div class="card-label">Total Analisado</div>
                <div class="card-value">{total_domains}</div>
                <div class="card-sub">Domínios verificados</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
            <div class="card">
                <div class="card-label">Maliciosos</div>
                <div class="card-value status-bad">{malicious_domains}</div>
                <div class="card-sub">Ameaças detectadas</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
            <div class="card">
                <div class="card-label">Suspeitos</div>
                <div class="card-value status-warn">{suspicious_domains}</div>
                <div class="card-sub">Possíveis ameaças</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
            <div class="card">
                <div class="card-label">Limpos</div>
                <div class="card-value status-ok">{clean_domains}</div>
                <div class="card-sub">Sem ameaças</div>
            </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### 🔍 Resultados Detalhados")
    
    # Mostrar cada domínio
    if len(domain_list) == 1:
        domain = domain_list[0]
        result = st.session_state.analyzed_domains[domain]
        render_domain_result(domain, result)
    else:
        # Usar tabs para múltiplos domínios
        tabs = st.tabs(domain_list)
        for tab, domain in zip(tabs, domain_list):
            with tab:
                result = st.session_state.analyzed_domains[domain]
                render_domain_result(domain, result)
    
    # ============================================
    # SEÇÃO DE DOWNLOAD
    # ============================================
    st.markdown("---")
    st.markdown("## 📥 Exportar Resultados")
    
    col1, col2, col3 = st.columns(3)
    
    # Preparar dados para exportação
    export_data = []
    for domain, result in st.session_state.analyzed_domains.items():
        export_data.append({
            'Domínio': domain,
            'Status': result.get('status', 'error'),
            'Reputação': result.get('reputation', 0),
            'Maliciosos': result.get('malicious_count', 0),
            'Suspeitos': result.get('suspicious_count', 0),
            'Total Detecções': result.get('malicious_count', 0) + result.get('suspicious_count', 0),
            'Categorias': ', '.join([f"{k}: {v}" for k, v in result.get('categories', {}).items()])
        })
    
    with col1:
        csv_data = ResultFormatter.format_for_csv(export_data)
        st.download_button(
            label="📥 Baixar CSV",
            data=csv_data,
            file_name=f"domain_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    with col2:
        json_data = ResultFormatter.format_for_json(export_data)
        st.download_button(
            label="📥 Baixar JSON",
            data=json_data,
            file_name=f"domain_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col3:
        txt_data = ResultFormatter.format_for_txt(export_data, 'domain')
        st.download_button(
            label="📥 Baixar TXT",
            data=txt_data,
            file_name=f"domain_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )
    
    # Botão para limpar
    st.markdown("---")
    if st.button("🗑️ Limpar Análises", use_container_width=True):
        st.session_state.analyzed_domains = {}
        st.rerun()

else:
    # Estado inicial
    st.info("""
    ℹ️ **Como usar:**
    1. Cole um domínio ou URL no campo acima
    2. Clique em "Analisar" para ver os resultados instantaneamente
    3. Os resultados aparecerão diretamente nesta página com:
       - **Status Visual**: Malicioso, Suspeito ou Limpo
       - **Métricas Destacadas**: Detecções maliciosas, suspeitas e reputação
       - **Categorias**: Classificações do domínio
       - **Resumo Geral**: Estatísticas consolidadas de múltiplas análises
    4. Exporte os resultados em CSV, JSON ou TXT
    """)
