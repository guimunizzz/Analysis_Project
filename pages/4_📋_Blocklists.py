import streamlit as st
import pandas as pd
import json
from pathlib import Path
from datetime import datetime
import logging
from styles.theme import get_common_styles, get_sidebar_logo_html

st.set_page_config(page_title="Listas de Bloqueio", page_icon="📋", layout="wide")

# Apply common styles from theme
st.markdown(get_common_styles(), unsafe_allow_html=True)

# Add sidebar logo
with st.sidebar:
    st.markdown(get_sidebar_logo_html(), unsafe_allow_html=True)

logger = logging.getLogger(__name__)

# Page header with consistent design
st.markdown("""
    <div class="page-shell">
      <div class="page-shell-header">
        <div>
          <div class="page-shell-title">
            📋 Listas de Bloqueio
          </div>
          <div class="page-shell-subtitle">
            Gerencie seus IPs, hashes e domínios bloqueados de forma centralizada
          </div>
        </div>
        <span class="page-shell-badge">Security Management • Blocklist</span>
      </div>
    </div>
""", unsafe_allow_html=True)

# Configuração de arquivos
BLOCKLIST_FILE = Path("data/blocklists.json")
BLOCKLIST_FILE.parent.mkdir(exist_ok=True)

def load_blocklists():
    """Carrega listas de bloqueio do arquivo"""
    if BLOCKLIST_FILE.exists():
        try:
            with open(BLOCKLIST_FILE, 'r') as f:
                return json.load(f)
        except:
            return {'ips': [], 'hashes': [], 'domains': []}
    return {'ips': [], 'hashes': [], 'domains': []}

def save_blocklists(blocklists):
    """Salva listas de bloqueio no arquivo"""
    try:
        with open(BLOCKLIST_FILE, 'w') as f:
            json.dump(blocklists, f, indent=2)
        return True
    except Exception as e:
        logger. error(f"Erro ao salvar listas de bloqueio: {str(e)}")
        return False

def add_to_blocklist(blocklist_type: str, item: str, reason: str = ""):
    """Adiciona um item à lista de bloqueio"""
    item = item.strip()
    reason = reason.strip()
    if not item:
        return False

    blocklists = load_blocklists()
    
    new_entry = {
        'value': item,
        'reason': reason,
        'added_at': datetime.now().isoformat(),
        'added_by': st.session_state.get('username', 'Anonymous')
    }
    
    if blocklist_type not in blocklists:
        blocklists[blocklist_type] = []
    
    # Verifica se já existe
    if not any(e['value'] == item for e in blocklists[blocklist_type]):
        blocklists[blocklist_type].append(new_entry)
        return save_blocklists(blocklists)
    
    return False

def remove_from_blocklist(blocklist_type: str, item: str):
    """Remove um item da lista de bloqueio"""
    blocklists = load_blocklists()
    
    if blocklist_type in blocklists:
        blocklists[blocklist_type] = [
            e for e in blocklists[blocklist_type] if e['value'] != item
        ]
        return save_blocklists(blocklists)
    
    return False

def export_blocklist(blocklist_type: str, format: str = 'txt'):
    """Exporta uma lista de bloqueio em diferentes formatos"""
    blocklists = load_blocklists()
    items = blocklists.get(blocklist_type, [])
    
    if format == 'txt':
        # Formato simples, um por linha
        return '\n'.join([item['value'] for item in items])
    
    elif format == 'csv':
        # Formato CSV com detalhes
        lines = ['Value,Reason,Added At,Added By']
        for item in items:
            value = item. get('value', '')
            reason = item.get('reason', '').replace(',', ';')
            added_at = item.get('added_at', '')
            added_by = item.get('added_by', 'Anonymous')
            lines.append(f'"{value}","{reason}","{added_at}","{added_by}"')
        return '\n'.join(lines)
    
    elif format == 'json':
        # Formato JSON completo
        return json.dumps(items, indent=2)
    
    return ""

# Abas principais
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔴 IPs Bloqueados",
    "🔗 Hashes Bloqueados",
    "🌐 Domínios Bloqueados",
    "➕ Adicionar Bloqueio",
    "📥 Exportar/Importar"
])

# Carregar listas
blocklists = load_blocklists()

# TAB 1: IPs Bloqueados
with tab1:
    st.subheader("🔴 IPs Bloqueados")
    
    ip_blocklist = blocklists. get('ips', [])
    
    if ip_blocklist:
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.metric("Total de IPs Bloqueados", len(ip_blocklist))
        
        # DataFrame com IPs
        df_ips = pd.DataFrame([
            {
                'IP': entry['value'],
                'Motivo': entry.get('reason', 'N/A'),
                'Data de Adição': entry.get('added_at', ''). split('T')[0],
                'Adicionado Por': entry.get('added_by', 'Anonymous')
            }
            for entry in ip_blocklist
        ])
        
        filter_ip = st.text_input("Filtrar por IP ou motivo", key="ip_filter")
        df_ips_to_show = df_ips
        if filter_ip:
            term = filter_ip.lower()
            df_ips_to_show = df_ips[
                df_ips.apply(
                    lambda row: term in str(row['IP']).lower() or term in str(row['Motivo']).lower(),
                    axis=1
                )
            ]
            st.caption(f"{len(df_ips_to_show)} resultado(s) após filtro")
        
        st.dataframe(df_ips_to_show, use_container_width=True)
        
        # Opções de remoção
        st.markdown("---")
        st.subheader("🗑️ Remover IPs")
        
        col1, col2 = st. columns([3, 1])
        with col1:
            ip_to_remove = st.selectbox(
                "Selecione um IP para remover:",
                [item['value'] for item in ip_blocklist],
                key="ip_remove_select"
            )
        
        with col2:
            if st.button("🗑️ Remover", key="ip_remove_btn"):
                if remove_from_blocklist('ips', ip_to_remove):
                    st.success(f"✅ IP {ip_to_remove} removido da lista de bloqueio")
                    st.rerun()
                else:
                    st.error("❌ Erro ao remover IP")
        
        # Busca rápida
        st.markdown("---")
        st.subheader("🔍 Buscar IP")
        search_ip = st.text_input("Digite um IP para buscar:")
        
        if search_ip:
            matches = [item for item in ip_blocklist if search_ip in item['value']]
            if matches:
                st.success(f"✅ {len(matches)} resultado(s) encontrado(s)")
                df_matches = pd.DataFrame([
                    {
                        'IP': item['value'],
                        'Motivo': item.get('reason', 'N/A'),
                        'Data': item.get('added_at', '').split('T')[0]
                    }
                    for item in matches
                ])
                st.dataframe(df_matches, use_container_width=True)
            else:
                st.info("ℹ️ Nenhum resultado encontrado")
    
    else:
        st. info("ℹ️ Nenhum IP bloqueado no momento")


# TAB 2: Hashes Bloqueados
with tab2:
    st.subheader("🔗 Hashes Bloqueados")
    
    hash_blocklist = blocklists.get('hashes', [])
    
    if hash_blocklist:
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.metric("Total de Hashes Bloqueados", len(hash_blocklist))
        
        # DataFrame com Hashes
        df_hashes = pd.DataFrame([
            {
                'Hash': entry['value'][:32] + '...' if len(entry['value']) > 32 else entry['value'],
                'Hash Completo': entry['value'],
                'Motivo': entry.get('reason', 'N/A'),
                'Data de Adição': entry.get('added_at', '').split('T')[0],
                'Adicionado Por': entry.get('added_by', 'Anonymous')
            }
            for entry in hash_blocklist
        ])
        
        filter_hash = st.text_input("Filtrar por hash ou motivo", key="hash_filter")
        df_hashes_to_show = df_hashes
        if filter_hash:
            term = filter_hash.lower()
            df_hashes_to_show = df_hashes[
                df_hashes.apply(
                    lambda row: term in str(row['Hash Completo']).lower() or term in str(row['Motivo']).lower(),
                    axis=1
                )
            ]
            st.caption(f"{len(df_hashes_to_show)} resultado(s) após filtro")
        
        st.dataframe(df_hashes_to_show, use_container_width=True)
        
        # Opções de remoção
        st.markdown("---")
        st.subheader("🗑️ Remover Hashes")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            hash_options = [f"{item['value'][:16]}...  ({item. get('reason', 'Sem motivo')})" for item in hash_blocklist]
            hash_selected = st.selectbox(
                "Selecione um hash para remover:",
                range(len(hash_blocklist)),
                format_func=lambda x: hash_options[x],
                key="hash_remove_select"
            )
        
        with col2:
            if st.button("🗑️ Remover", key="hash_remove_btn"):
                hash_to_remove = hash_blocklist[hash_selected]['value']
                if remove_from_blocklist('hashes', hash_to_remove):
                    st.success(f"✅ Hash removido da lista de bloqueio")
                    st.rerun()
                else:
                    st.error("❌ Erro ao remover hash")
        
        # Estatísticas
        st.markdown("---")
        st.subheader("📊 Estatísticas de Hashes")
        
        col1, col2 = st. columns(2)
        with col1:
            st.metric("Com Motivo Registrado", sum(1 for h in hash_blocklist if h. get('reason')))
        with col2:
            st.metric("Sem Motivo", sum(1 for h in hash_blocklist if not h.get('reason')))
    
    else:
        st. info("ℹ️ Nenhum hash bloqueado no momento")


# TAB 3: Domínios Bloqueados
with tab3:
    st.subheader("🌐 Domínios Bloqueados")
    
    domain_blocklist = blocklists.get('domains', [])
    
    if domain_blocklist:
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.metric("Total de Domínios Bloqueados", len(domain_blocklist))
        
        # DataFrame com Domínios
        df_domains = pd.DataFrame([
            {
                'Domínio': entry['value'],
                'Motivo': entry.get('reason', 'N/A'),
                'Data de Adição': entry.get('added_at', '').split('T')[0],
                'Adicionado Por': entry.get('added_by', 'Anonymous')
            }
            for entry in domain_blocklist
        ])
        
        filter_domain = st.text_input("Filtrar por domínio ou motivo", key="domain_filter")
        df_domains_to_show = df_domains
        if filter_domain:
            term = filter_domain.lower()
            df_domains_to_show = df_domains[
                df_domains.apply(
                    lambda row: term in str(row['Domínio']).lower() or term in str(row['Motivo']).lower(),
                    axis=1
                )
            ]
            st.caption(f"{len(df_domains_to_show)} resultado(s) após filtro")
        
        st.dataframe(df_domains_to_show, use_container_width=True)
        
        # Opções de remoção
        st. markdown("---")
        st. subheader("🗑️ Remover Domínios")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            domain_to_remove = st.selectbox(
                "Selecione um domínio para remover:",
                [item['value'] for item in domain_blocklist],
                key="domain_remove_select"
            )
        
        with col2:
            if st. button("🗑️ Remover", key="domain_remove_btn"):
                if remove_from_blocklist('domains', domain_to_remove):
                    st.success(f"✅ Domínio {domain_to_remove} removido da lista de bloqueio")
                    st.rerun()
                else:
                    st.error("❌ Erro ao remover domínio")
        
        # TLDs mais comuns
        st.markdown("---")
        st.subheader("📈 Domínios por TLD")
        
        tlds = {}
        for item in domain_blocklist:
            domain = item['value']
            tld = domain.split('.')[-1] if '.' in domain else 'N/A'
            tlds[tld] = tlds.get(tld, 0) + 1
        
        df_tlds = pd.DataFrame(list(tlds.items()), columns=['TLD', 'Quantidade'])
        df_tlds = df_tlds.sort_values('Quantidade', ascending=False)
        
        st.bar_chart(df_tlds. set_index('TLD'))
    
    else:
        st.info("ℹ️ Nenhum domínio bloqueado no momento")


# TAB 4: Adicionar Bloqueio
with tab4:
    st.subheader("➕ Adicionar Item à Lista de Bloqueio")
    
    tipo_bloqueio = st.radio(
        "Tipo de bloqueio:",
        ["IP", "Hash", "Domínio"],
        horizontal=True
    )
    
    if tipo_bloqueio == "IP":
        col1, col2 = st.columns([2, 1])
        with col1:
            ip_input = st.text_input("Digite o IP:")
            ip_reason = st.text_input("Motivo do bloqueio:", key="ip_reason")
        with col2:
            st.write("")
            st.write("")
            if st.button("➕ Adicionar IP"):
                if not ip_input.strip():
                    st.error("❌ Digite um IP válido")
                elif not ip_reason.strip():
                    st.warning("⚠️ Informe um motivo para o bloqueio")
                elif add_to_blocklist('ips', ip_input.strip(), ip_reason.strip()):
                    st.success(f"✅ IP {ip_input} adicionado à lista de bloqueio")
                    st.rerun()
                else:
                    st.warning(f"⚠️ IP {ip_input} já está na lista de bloqueio")
    
    elif tipo_bloqueio == "Hash":
        col1, col2 = st.columns([2, 1])
        with col1:
            hash_input = st.text_input("Digite o hash (MD5, SHA1 ou SHA256):")
            hash_reason = st.text_input("Motivo do bloqueio:", key="hash_reason_single")
        with col2:
            st.write("")
            st.write("")
            if st.button("➕ Adicionar Hash"):
                if not hash_input.strip():
                    st.error("❌ Digite um hash válido")
                elif not hash_reason.strip():
                    st.warning("⚠️ Informe um motivo para o bloqueio")
                elif add_to_blocklist('hashes', hash_input.strip(), hash_reason.strip()):
                    st.success(f"✅ Hash adicionado à lista de bloqueio")
                    st.rerun()
                else:
                    st.warning(f"⚠️ Hash já está na lista de bloqueio")
    
    elif tipo_bloqueio == "Domínio":
        col1, col2 = st. columns([2, 1])
        with col1:
            domain_input = st.text_input("Digite o domínio:")
            domain_reason = st.text_input("Motivo do bloqueio:", key="domain_reason_single")
        with col2:
            st.write("")
            st.write("")
            if st.button("➕ Adicionar Domínio"):
                if not domain_input.strip():
                    st.error("❌ Digite um domínio válido")
                elif not domain_reason.strip():
                    st.warning("⚠️ Informe um motivo para o bloqueio")
                elif add_to_blocklist('domains', domain_input.strip(), domain_reason.strip()):
                    st.success(f"✅ Domínio {domain_input} adicionado à lista de bloqueio")
                    st.rerun()
                else:
                    st.warning(f"⚠️ Domínio {domain_input} já está na lista de bloqueio")
    
    # Adicionar em lote
    st.markdown("---")
    st.subheader("📦 Adicionar em Lote")
    
    lote_type = st.selectbox("Tipo de bloqueio (lote):", ["IP", "Hash", "Domínio"])
    lote_text = st.text_area(
        f"Cole múltiplos {lote_type. lower()}s (um por linha):",
        height=100
    )
    lote_reason = st.text_input("Motivo comum para todos:")
    
    if st.button("📦 Adicionar em Lote"):
        items = [item. strip() for item in lote_text.split('\n') if item.strip()]
        
        if items:
            lote_type_key = lote_type.lower() + 's'
            added_count = 0
            
            for item in items:
                if add_to_blocklist(lote_type_key, item, lote_reason):
                    added_count += 1
            
            st.success(f"✅ {added_count}/{len(items)} itens adicionados à lista de bloqueio")
            st.rerun()
        else:
            st.error("❌ Digite pelo menos um item")


# TAB 5: Exportar/Importar
with tab5:
    st.subheader("📥 Exportar/Importar Listas de Bloqueio")
    
    export_col, import_col = st.columns(2)
    
    # EXPORTAR
    with export_col:
        st.subheader("📤 Exportar Listas")
        
        export_type = st.selectbox(
            "O que deseja exportar?",
            ["Todos", "IPs", "Hashes", "Domínios"],
            key="export_type"
        )
        
        export_format = st.radio(
            "Formato de exportação:",
            ["Texto (. txt)", "CSV (.csv)", "JSON (.json)"],
            key="export_format"
        )
        
        if st.button("📤 Gerar Exportação"):
            export_data = ""
            filename = ""
            mime_type = "text/plain"
            
            if export_format == "Texto (.txt)":
                mime_type = "text/plain"
                ext = ".txt"
            elif export_format == "CSV (. csv)":
                mime_type = "text/csv"
                ext = ".csv"
            else:
                mime_type = "application/json"
                ext = ".json"
            
            format_key = export_format.split('(')[1].replace(')', '')
            
            if export_type == "Todos":
                # Exporta todos os tipos
                all_data = {
                    'ips': export_blocklist('ips', format_key),
                    'hashes': export_blocklist('hashes', format_key),
                    'domains': export_blocklist('domains', format_key)
                }
                if format_key == 'json':
                    export_data = json.dumps(all_data, indent=2)
                else:
                    export_data = f"=== IPs ===\n{all_data['ips']}\n\n=== HASHES ===\n{all_data['hashes']}\n\n=== DOMÍNIOS ===\n{all_data['domains']}"
                filename = f"blocklists_complete_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            
            else:
                blocklist_key = export_type.lower() + 's'
                export_data = export_blocklist(blocklist_key, format_key)
                filename = f"blocklist_{export_type. lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            
            st.download_button(
                label=f"💾 Baixar {export_type} ({export_format})",
                data=export_data,
                file_name=filename,
                mime=mime_type
            )
    
    # IMPORTAR
    with import_col:
        st.subheader("📥 Importar Listas")
        
        uploaded_file = st.file_uploader(
            "Selecione um arquivo para importar:",
            type=['txt', 'csv', 'json'],
            key="import_file"
        )
        
        if uploaded_file:
            file_content = uploaded_file.read(). decode('utf-8')
            import_type = st.selectbox(
                "Tipo de importação:",
                ["IPs", "Hashes", "Domínios"],
                key="import_type"
            )
            
            if st.button("📥 Importar"):
                items = []
                
                if uploaded_file.type == "text/plain":
                    items = [line.strip() for line in file_content.split('\n') if line.strip()]
                elif uploaded_file.type == "text/csv":
                    lines = file_content.split('\n')[1:]  # Pula header
                    items = [line. split(',')[0]. strip(). strip('"') for line in lines if line.strip()]
                elif uploaded_file.type == "application/json":
                    try:
                        data = json.loads(file_content)
                        if isinstance(data, list):
                            items = [item['value'] if isinstance(item, dict) else item for item in data]
                        elif isinstance(data, dict) and 'ips' in data:
                            import_type = "IPs"
                            items = data['ips']
                    except:
                        st.error("❌ Erro ao ler JSON")
                
                if items:
                    import_type_key = import_type.lower() + 's'
                    added = 0
                    
                    for item in items:
                        if add_to_blocklist(import_type_key, item. strip(), "Importado"):
                            added += 1
                    
                    st. success(f"✅ {added}/{len(items)} itens importados com sucesso")
                    st.rerun()
    
    st.markdown("---")
    st.subheader("🔎 Busca rápida nas blocklists")
    global_query = st.text_input(
        "Busque por valor ou motivo em todas as listas:",
        key="blocklist_global_search"
    )
    if global_query:
        results = []
        term = global_query.lower()
        for item_type, items in blocklists.items():
            for item in items:
                value = item.get('value', '')
                reason = item.get('reason', '')
                if term in value.lower() or term in reason.lower():
                    results.append({
                        "Tipo": item_type.rstrip('s').upper(),
                        "Valor": value,
                        "Motivo": reason or "Sem motivo",
                        "Adicionado Em": item.get('added_at', '')[:10]
                    })
        if results:
            st.dataframe(pd.DataFrame(results), use_container_width=True)
        else:
            st.info("ℹ️ Nenhum resultado para o termo informado.")

    # Estatísticas Gerais
    st.markdown("---")
    st.subheader("📊 Estatísticas Gerais das Listas")
    
    col1, col2, col3 = st. columns(3)
    with col1:
        st.metric("Total de IPs", len(blocklists. get('ips', [])))
    with col2:
        st.metric("Total de Hashes", len(blocklists.get('hashes', [])))
    with col3:
        st. metric("Total de Domínios", len(blocklists.get('domains', [])))
    
    total_items = sum(len(blocklists.get(key, [])) for key in ['ips', 'hashes', 'domains'])
    st.info(f"📈 Total de itens na lista de bloqueio: **{total_items}**")
    
    # Itens mais recentes
    st.markdown("---")
    st.subheader("🕐 Itens Adicionados Recentemente")
    
    all_items = []
    for item_type, items in blocklists.items():
        for item in items:
            all_items.append({
                'Tipo': item_type. rstrip('s'). upper(),
                'Valor': item['value'],
                'Data': item. get('added_at', ''). split('T')[0],
                'Motivo': item.get('reason', 'N/A')[:30]
            })
    
    if all_items:
        df_recent = pd.DataFrame(all_items)
        df_recent['Data'] = pd.to_datetime(df_recent['Data'])
        df_recent = df_recent.sort_values('Data', ascending=False). head(10)
        
        st.dataframe(df_recent, use_container_width=True)
    else:
        st.info("ℹ️ Nenhum item na lista de bloqueio")
