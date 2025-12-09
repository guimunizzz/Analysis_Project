import streamlit as st
import pandas as pd
from config.settings import load_config
from services.virustotal import VirusTotalService
from utils.validators import validate_hash
from utils.parsers import TextParser
from utils.formatters import ResultFormatter
from styles.theme import get_common_styles, get_sidebar_logo_html
import time
from datetime import datetime
import json
from pathlib import Path

st.set_page_config(page_title="Análise de Hash", page_icon="🔗", layout="wide")

# Apply common styles from theme
st.markdown(get_common_styles(), unsafe_allow_html=True)

# Additional styles specific to Hash Analysis page
st.markdown("""
    <style>
    .hash-result-container {
        border-radius: 10px;
        padding: 20px;
        margin: 15px 0;
        border-left: 5px solid;
    }
    
    .malicious {
        background-color: rgba(239, 68, 68, 0.1);
        border-left-color: #ef4444;
    }
    
    .suspicious {
        background-color: rgba(249, 115, 22, 0.1);
        border-left-color: #f97316;
    }
    
    .clean {
        background-color: rgba(34, 197, 94, 0.1);
        border-left-color: #22c55e;
    }
    
    .undetected {
        background-color: rgba(107, 114, 128, 0.1);
        border-left-color: #6b7280;
    }
    
    .hash-header {
        font-family: 'Courier New', monospace;
        font-size: 14px;
        word-break: break-all;
        padding: 10px;
        background-color: rgba(0, 0, 0, 0.05);
        border-radius: 5px;
        margin: 10px 0;
    }
    
    .detection-box {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 15px;
        margin: 20px 0;
    }
    
    .detection-item {
        text-align: center;
        padding: 15px;
        border-radius: 8px;
        background-color: rgba(0, 0, 0, 0.02);
        border: 1px solid rgba(0, 0, 0, 0.1);
    }
    
    .detection-number {
        font-size: 32px;
        font-weight: bold;
        color: #ef4444;
    }
    
    .detection-number-safe {
        font-size: 32px;
        font-weight: bold;
        color: #22c55e;
    }
    
    .detection-label {
        font-size: 12px;
        color: #6b7280;
        margin-top: 5px;
    }
    
    .vendor-detected {
        background-color: rgba(239, 68, 68, 0.15);
        border-left: 4px solid #ef4444;
        padding: 10px;
        margin: 8px 0;
        border-radius: 6px;
    }
    
    .vendor-suspicious {
        background-color: rgba(249, 115, 22, 0.15);
        border-left: 4px solid #f97316;
        padding: 10px;
        margin: 8px 0;
        border-radius: 6px;
    }
    
    .threat-badge {
        display: inline-block;
        background-color: #ef4444;
        color: white;
        padding: 6px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
        margin: 5px 5px 5px 0;
    }
    
    .family-badge {
        display: inline-block;
        background-color: #8b5cf6;
        color: white;
        padding: 6px 12px;
        border-radius: 20px;
        font-size: 12px;
        margin: 5px 5px 5px 0;
    }
    
    .vendor-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
        gap: 12px;
        margin: 20px 0;
    }
    
    .vendor-item {
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #e5e7eb;
        font-size: 13px;
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
            🔗 Análise de Hash
          </div>
          <div class="page-shell-subtitle">
            Verifique a reputação de hashes de arquivo (MD5, SHA1, SHA256) com detalhes de vendors e threat labels
          </div>
        </div>
        <span class="page-shell-badge">Threat Intelligence • Hash</span>
      </div>
    </div>
""", unsafe_allow_html=True)

config = load_config()

if not config.get('virustotal_api_key'):
    st.error("❌ VirusTotal API não configurada. Acesse Configurações.")
    st.stop()

vt_service = VirusTotalService(config['virustotal_api_key'])

BLOCKLIST_FILE = Path("data/blocklists.json")

def get_blocklist_entry(value: str, list_key: str):
    try:
        data = json.loads(BLOCKLIST_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    normalized = value.lower()
    for entry in data.get(list_key, []):
        entry_value = entry.get('value', '')
        if entry_value.lower() == normalized:
            return entry
    return None

# Inicializar session state
if 'analyzed_hashes' not in st.session_state:
    st.session_state.analyzed_hashes = {}

# ============================================
# SEÇÃO DE ENTRADA
# ============================================
col1, col2 = st.columns([4, 1])

with col1:
    st.markdown('<div class="ip-input-label">Hash para Análise</div>', unsafe_allow_html=True)
    hash_input = st.text_input(
        label="",
        placeholder="Ex.: d41d8cd98f00b204e9800998ecf8427e (MD5, SHA1 ou SHA256)",
        key="hash_input_main"
    )
    st.markdown('<div class="ip-helper">Cole um hash de arquivo para análise detalhada. Resultados completos de VirusTotal serão exibidos abaixo.</div>', unsafe_allow_html=True)

with col2:
    st.write("")
    st.write("")
    analyze_single = st.button("🔍 Analisar", key="analyze_single_btn", use_container_width=True)

# Analisar um único hash
if analyze_single and hash_input.strip():
    hash_value = hash_input.strip().lower()
    
    # Validar formato
    is_valid, hash_type = validate_hash(hash_value)
    
    if not is_valid:
        st.error("❌ Formato de hash inválido! Use MD5 (32), SHA1 (40) ou SHA256 (64) caracteres hexadecimais.")
    else:
        # Analisar
        with st.spinner(f"🔄 Analisando {hash_type} hash..."):
            vt_result = vt_service.analyze_hash(hash_value)
            st.session_state.analyzed_hashes[hash_value] = {
                'type': hash_type,
                'result': vt_result
            }

# ============================================
# SEÇÃO DE UPLOAD EM LOTE
# ============================================
st.markdown("---")
st.markdown("### 📤 Análise em Lote")

with st.expander("📦 Carregar múltiplos hashes de arquivo"):
    uploaded_file = st.file_uploader("Selecione um arquivo txt ou csv:", type=['txt', 'csv'])
    
    if uploaded_file and st.button("📤 Processar Arquivo", key="process_file_hash"):
        content = uploaded_file.read().decode('utf-8')
        hashes = TextParser.parse_hashes(content)
        
        if hashes:
            st.success(f"✅ {len(hashes)} hash(es) válido(s) encontrado(s). Iniciando análise...")
            
            progress_bar = st.progress(0)
            status_placeholder = st.empty()
            
            for idx, (hash_value, hash_type) in enumerate(hashes):
                status_placeholder.text(f"Analisando {idx + 1}/{len(hashes)}: {hash_value[:20]}...")
                
                vt_result = vt_service.analyze_hash(hash_value)
                st.session_state.analyzed_hashes[hash_value] = {
                    'type': hash_type,
                    'result': vt_result
                }
                
                progress_bar.progress((idx + 1) / len(hashes))
                time.sleep(0.1)  # Rate limiting
            
            progress_bar.empty()
            status_placeholder.empty()
            st.success(f"✅ Análise de {len(hashes)} hash(es) concluída!")
        else:
            st.error("❌ Nenhum hash válido encontrado no arquivo")

# ============================================
# FUNÇÃO PARA RENDERIZAR RESULTADO
# ============================================

def render_hash_result(hash_value, hash_data):
    """Renderiza um resultado de análise de hash"""
    result = hash_data['result']
    hash_type = hash_data['type']
    
    # Determinar o status
    if result. get('status') == 'not_found':
        status = 'undetected'
        status_text = "Não encontrado no VirusTotal"
        status_color = "🟢"
    elif result.get('status') == 'error':
        status = 'error'
        status_text = f"Erro: {result.get('message', 'Erro desconhecido')}"
        status_color = "⚠️"
    else:
        detections = result.get('detections', 0)
        if detections == 0:
            status = 'clean'
            status_text = "Limpo - Nenhuma detecção"
            status_color = "🟢"
        elif detections <= 3:
            status = 'suspicious'
            status_text = "Suspeito - Poucas detecções"
            status_color = "🟡"
        else:
            status = 'malicious'
            status_text = "Malicioso - Múltiplas detecções"
            status_color = "🔴"
    
    # Exibir resultado principal
    st.markdown(f"""
        <div class="hash-result-container {status}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h3 style="margin: 0;">{status_color} {status_text}</h3>
                    <p style="color: #6b7280; margin: 5px 0 0 0;">Tipo: {hash_type}</p>
                </div>
            </div>
            <div class="hash-header">{hash_value}</div>
        </div>
    """, unsafe_allow_html=True)

    block_entry = get_blocklist_entry(hash_value, "hashes")
    if block_entry:
        st.markdown(
            f"""
            <div class="hash-result-container malicious" style="border-left-color:#ef4444; background: rgba(239,68,68,0.08);">
                <div style="display:flex; justify-content: space-between; align-items:center;">
                    <div>
                        <h4 style="margin:0;">🚫 Hash presente na blocklist</h4>
                        <p style="margin:4px 0 0 0; color:#6b7280;">Motivo: {block_entry.get('reason', 'Sem motivo')}</p>
                        <p style="margin:2px 0 0 0; color:#9ca3af; font-size: 12px;">Adicionado por {block_entry.get('added_by', 'N/A')} em {block_entry.get('added_at', '')[:10]}</p>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    
    # Se não houver erro, mostrar detalhes
    if result.get('status') not in ['error', 'not_found']:
        detections = result.get('detections', 0)
        suspicious = result.get('suspicious', 0)
        undetected = result.get('undetected', 0)
        total_scans = result.get('total_scans', 0)
        
        # Box de detecções
        st.markdown("""<div class="detection-box">""", unsafe_allow_html=True)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
                <div class="detection-item">
                    <div class="detection-number">{detections}</div>
                    <div class="detection-label">MALICIOSOS</div>
                </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st. markdown(f"""
                <div class="detection-item">
                    <div class="detection-number" style="color: #f97316;">{suspicious}</div>
                    <div class="detection-label">SUSPEITOS</div>
                </div>
            """, unsafe_allow_html=True)
        
        with col3:
            taxa_deteccao = (detections / total_scans * 100) if total_scans > 0 else 0
            st.markdown(f"""
                <div class="detection-item">
                    <div class="detection-number">{taxa_deteccao:.1f}%</div>
                    <div class="detection-label">TAXA DE DETECÇÃO</div>
                </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown(f"""
                <div class="detection-item">
                    <div class="detection-number-safe">{total_scans}</div>
                    <div class="detection-label">TOTAL DE SCANNERS</div>
                </div>
            """, unsafe_allow_html=True)
        
        st.markdown("""</div>""", unsafe_allow_html=True)
        
        # Informações de Arquivo
        st.markdown("### 📄 Informações do Arquivo")
        
        file_info_col1, file_info_col2, file_info_col3 = st.columns(3)
        
        with file_info_col1:
            st.metric("Tipo de Arquivo", result.get('file_type', 'Desconhecido'))
        
        with file_info_col2:
            size = result.get('size', 'N/A')
            if isinstance(size, int):
                size = f"{size / 1024:.2f} KB" if size < 1024*1024 else f"{size / (1024*1024):. 2f} MB"
            st.metric("Tamanho", size)
        
        with file_info_col3:
            last_date = result.get('last_analysis_date', 'N/A')
            if isinstance(last_date, int):
                last_date = datetime.fromtimestamp(last_date).strftime('%d/%m/%Y')
            st.metric("Última Análise", last_date)
        
        # THREAT CATEGORIES
        threat_categories = result.get('threat_categories', [])
        if threat_categories:
            st.markdown("### 🚨 Categorias de Ameaça")
            threat_html = ""
            for category in threat_categories:
                threat_html += f'<span class="threat-badge">{category. upper()}</span>'
            st. markdown(threat_html, unsafe_allow_html=True)
        
        # FAMILY LABELS
        family_labels = result.get('family_labels', {})
        if family_labels:
            st.markdown("### 🦠 Famílias de Malware Detectadas")
            family_html = ""
            for family, count in sorted(family_labels.items(), key=lambda x: x[1], reverse=True):
                family_html += f'<span class="family-badge">{family} ({count})</span>'
            st.markdown(family_html, unsafe_allow_html=True)
        
        # VENDORS QUE DETECTARAM
        detected_vendors = result.get('detected_vendors', [])
        if detected_vendors:
            st. markdown(f"### 🛡️ Vendors que Detectaram ({len(detected_vendors)} de {total_scans})")
            
            # Separar por categoria
            malicious_vendors = [v for v in detected_vendors if v['category'] == 'malicious']
            suspicious_vendors = [v for v in detected_vendors if v['category'] == 'suspicious']
            
            # Mostrar maliciosos primeiro
            if malicious_vendors:
                st.markdown("#### 🔴 Detectados como Malicioso")
                for vendor in malicious_vendors[:15]:  # Mostrar primeiros 15
                    st. markdown(f"""
                        <div class="vendor-detected">
                            <b>{vendor['engine_name']}</b><br>
                            <small>Resultado: {vendor['result']}</small><br>
                            <small style="color: #6b7280;">Atualização: {vendor['engine_update']}</small>
                        </div>
                    """, unsafe_allow_html=True)
                
                if len(malicious_vendors) > 15:
                    st. info(f"ℹ️ {len(malicious_vendors) - 15} vendors adicionais detectaram como malicioso")
            
            # Mostrar suspeitos
            if suspicious_vendors:
                st.markdown("#### 🟡 Detectados como Suspeito")
                for vendor in suspicious_vendors[:10]:  # Mostrar primeiros 10
                    st.markdown(f"""
                        <div class="vendor-suspicious">
                            <b>{vendor['engine_name']}</b><br>
                            <small>Resultado: {vendor['result']}</small><br>
                            <small style="color: #6b7280;">Atualização: {vendor['engine_update']}</small>
                        </div>
                    """, unsafe_allow_html=True)
                
                if len(suspicious_vendors) > 10:
                    st.info(f"ℹ️ {len(suspicious_vendors) - 10} vendors adicionais detectaram como suspeito")
        
        # HASHES ALTERNATIVOS
        st.markdown("### 🔗 Hashes Alternativos do Arquivo")
        
        hash_col1, hash_col2, hash_col3 = st.columns(3)
        
        with hash_col1:
            md5 = result.get('md5', 'N/A')
            st.text_input("MD5", value=md5 if md5 != 'N/A' else '', disabled=True)
        
        with hash_col2:
            sha1 = result.get('sha1', 'N/A')
            st.text_input("SHA1", value=sha1 if sha1 != 'N/A' else '', disabled=True)
        
        with hash_col3:
            sha256 = result.get('sha256', 'N/A')
            st.text_input("SHA256", value=sha256 if sha256 != 'N/A' else '', disabled=True)
        
        # NOMES DO ARQUIVO
        names = result.get('names', [])
        if names:
            st.markdown("### 📝 Nomes de Arquivo Conhecidos")
            for name in names[:10]:  # Mostrar primeiros 10
                st.code(name, language="text")
            if len(names) > 10:
                st.info(f"ℹ️ {len(names) - 10} nomes adicionais")

# ============================================
# SEÇÃO DE RESULTADOS
# ============================================
if st.session_state.analyzed_hashes:
    st.markdown("---")
    st.markdown("## 📊 Resultados da Análise")
    
    # Abas para cada hash
    hash_list = list(st.session_state.analyzed_hashes.keys())
    
    if len(hash_list) == 1:
        # Mostrar resultado único
        hash_value = hash_list[0]
        hash_data = st.session_state.analyzed_hashes[hash_value]
        
        render_hash_result(hash_value, hash_data)
    
    else:
        # Múltiplos resultados em abas
        st.write(f"**{len(hash_list)} hashes analisados:**")
        
        tabs = st.tabs([h[:16] + "..." for h in hash_list])
        
        for tab_idx, (tab, hash_value) in enumerate(zip(tabs, hash_list)):
            with tab:
                hash_data = st.session_state.analyzed_hashes[hash_value]
                render_hash_result(hash_value, hash_data)
    
    # ============================================
    # SEÇÃO DE DOWNLOAD
    # ============================================
    st.markdown("---")
    st.markdown("## 📥 Exportar Resultados")
    
    col1, col2, col3 = st.columns(3)
    
    # Preparar dados para exportação
    export_data = []
    for hash_value, hash_data in st.session_state.analyzed_hashes.items():
        result = hash_data['result']
        export_data.append({
            'Hash': hash_value,
            'Tipo': hash_data['type'],
            'Status': result.get('status', 'error'),
            'Maliciosos': result.get('detections', 0),
            'Suspeitos': result.get('suspicious', 0),
            'Total Scanners': result.get('total_scans', 0),
            'Tipo de Arquivo': result.get('file_type', 'N/A'),
            'Taxa Detecção (%)': round((result.get('detections', 0) / result.get('total_scans', 1) * 100), 2) if result.get('total_scans', 0) > 0 else 0,
            'Threat Categories': ', '.join(result.get('threat_categories', [])),
            'Family Labels': ', '.join([f"{k} ({v})" for k, v in result.get('family_labels', {}).items()])
        })
    
    with col1:
        csv_data = ResultFormatter.format_for_csv(export_data)
        st.download_button(
            label="📥 Baixar CSV",
            data=csv_data,
            file_name=f"hash_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    with col2:
        json_data = ResultFormatter.format_for_json(export_data)
        st.download_button(
            label="📥 Baixar JSON",
            data=json_data,
            file_name=f"hash_analysis_{pd. Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col3:
        txt_data = ResultFormatter.format_for_txt(export_data, 'hash')
        st.download_button(
            label="📥 Baixar TXT",
            data=txt_data,
            file_name=f"hash_analysis_{pd. Timestamp.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )
    
    # Botão para limpar
    st.markdown("---")
    if st.button("🗑️ Limpar Análises", use_container_width=True):
        st.session_state.analyzed_hashes = {}
        st.rerun()

else:
    # Estado inicial
    st.info("""
    ℹ️ **Como usar:**
    1. Cole um hash (MD5, SHA1 ou SHA256) no campo acima
    2. Clique em "Analisar" para obter os resultados completos
    3. Os resultados aparecerão em tempo real com:
       - **Categorias de Ameaça**: Tipos de ameaça detectadas
       - **Famílias de Malware**: Nomes das famílias de malware
       - **Vendors que Detectaram**: Lista completa de antivírus que detectaram
       - **Hashes Alternativos**: MD5, SHA1, SHA256 do arquivo
       - **Nomes Conhecidos**: Nomes do arquivo em sistemas infectados
    4. Exporte os resultados em CSV, JSON ou TXT
    """)
