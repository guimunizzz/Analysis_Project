import streamlit as st
import pandas as pd
from config.settings import load_config
from services.virustotal import VirusTotalService
from utils.parsers import TextParser
from utils. formatters import ResultFormatter
import time

st.set_page_config(page_title="Análise de Domínio", page_icon="🌐", layout="wide")

st.title("🌐 Análise de Domínio")
st.markdown("Verifique a reputação de domínios e URLs em múltiplas fontes")

config = load_config()

if not config.get('virustotal_api_key'):
    st.error("❌ VirusTotal API não configurada. Acesse Configurações.")
    st.stop()

vt_service = VirusTotalService(config['virustotal_api_key'])

# Abas
tab1, tab2, tab3, tab4 = st.tabs(["📝 Entrada Manual", "📤 Upload de Arquivo", "📊 Resultados", "📥 Download"])

with tab1:
    st.subheader("Inserir Domínios e URLs")
    st.markdown("Insira domínios ou URLs (um por linha)")
    
    domain_text = st.text_area(
        "Cole seus domínios/URLs aqui:",
        height=150,
        placeholder="example.com\nhttps://malicious-site.net\nphishing-url.com/login"
    )
    
    if st.button("🔍 Analisar Domínios", key="analyze_domain_btn"):
        if not domain_text.strip():
            st.warning("⚠️ Insira pelo menos um domínio")
        else:
            domains = TextParser.parse_domains(domain_text)
            urls = TextParser.parse_urls(domain_text)
            
            all_targets = list(set(domains + [u. split('/')[2] for u in urls]))
            
            if not all_targets:
                st.error("❌ Nenhum domínio válido encontrado")
            else:
                st.session_state.domains_to_analyze = all_targets
                st.success(f"✅ {len(all_targets)} domínio(s) válido(s) encontrado(s)")

with tab2:
    st.subheader("Upload de Arquivo")
    uploaded_file = st.file_uploader("Selecione um arquivo txt ou csv:", type=['txt', 'csv'])
    
    if uploaded_file and st.button("📤 Processar Arquivo", key="process_file_domain"):
        content = uploaded_file. read().decode('utf-8')
        domains = TextParser.parse_domains(content)
        urls = TextParser.parse_urls(content)
        
        all_targets = list(set(domains + [u.split('/')[2] for u in urls]))
        
        if all_targets:
            st.session_state.domains_to_analyze = all_targets
            st. success(f"✅ {len(all_targets)} domínio(s) válido(s) extraído(s)")
        else:
            st.error("❌ Nenhum domínio válido encontrado no arquivo")

with tab3:
    st. subheader("Resultados da Análise")
    
    if 'domains_to_analyze' in st.session_state:
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for idx, domain in enumerate(st.session_state.domains_to_analyze):
            status_text.text(f"Analisando {idx + 1}/{len(st.session_state.domains_to_analyze)}: {domain}")
            
            vt_result = vt_service.analyze_domain(domain)
            
            results.append({
                'domain': domain,
                'status': vt_result.get('status', 'error'),
                'reputation': vt_result.get('reputation', 0),
                'malicious_count': vt_result.get('malicious_count', 0),
                'suspicious_count': vt_result. get('suspicious_count', 0),
                'categories': vt_result.get('categories', {}),
                'vt_data': vt_result
            })
            
            progress_bar.progress((idx + 1) / len(st.session_state.domains_to_analyze))
            time.sleep(0.1)
        
        status_text.empty()
        
        # Criar DataFrame
        df_results = pd.DataFrame([
            {
                'Domínio': r['domain'],
                'Reputação': r['reputation'],
                'Maliciosos': r['malicious_count'],
                'Suspeitos': r['suspicious_count'],
                'Total Detecções': r['malicious_count'] + r['suspicious_count'],
                'Status': '🔴 Malicious' if r['malicious_count'] > 0 else ('🟡 Suspicious' if r['suspicious_count'] > 0 else '🟢 Clean')
            }
            for r in results
        ])
        
        st.dataframe(df_results, use_container_width=True)
        
        # Resumo
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Analisado", len(results))
        with col2:
            malicious = sum(1 for r in results if r['malicious_count'] > 0)
            st.metric("Maliciosos", malicious)
        with col3:
            suspicious = sum(1 for r in results if r['suspicious_count'] > 0 and r['malicious_count'] == 0)
            st. metric("Suspeitos", suspicious)
        with col4:
            clean = len(results) - malicious - suspicious
            st.metric("Limpos", clean)
        
        # Detalhes expandíveis
        st.markdown("---")
        st.subheader("📋 Detalhes Completos")
        
        for result in results:
            with st.expander(f"🔍 {result['domain']}"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st. metric("Reputação", result['reputation'])
                with col2:
                    st.metric("Maliciosos", result['malicious_count'])
                with col3:
                    st.metric("Suspeitos", result['suspicious_count'])
                
                if result['categories']:
                    st.markdown("**Categorias (VirusTotal):**")
                    for cat, value in result['categories'].items():
                        st.write(f"- {cat}: {value}")
        
        # Armazenar para download
        st.session_state.domain_results = results
        st. session_state.domain_df = df_results

with tab4:
    st.subheader("📥 Download de Relatórios")
    
    if 'domain_results' in st. session_state:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            csv_data = ResultFormatter.format_for_csv(st.session_state.domain_results)
            st.download_button(
                label="📥 Baixar CSV",
                data=csv_data,
                file_name=f"domain_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        with col2:
            json_data = ResultFormatter.format_for_json(st.session_state. domain_results)
            st. download_button(
                label="📥 Baixar JSON",
                data=json_data,
                file_name=f"domain_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        with col3:
            txt_data = ResultFormatter.format_for_txt(st.session_state.domain_results, 'domain')
            st.download_button(
                label="📥 Baixar TXT",
                data=txt_data,
                file_name=f"domain_analysis_{pd. Timestamp.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    else:
        st.info("ℹ️ Realize uma análise primeiro para gerar relatórios")