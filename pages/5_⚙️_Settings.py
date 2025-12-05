import streamlit as st
from config.settings import load_config, save_config
import requests

st.set_page_config(page_title="Configurações", page_icon="⚙️", layout="wide")

st.title("⚙️ Configurações")
st.markdown("Adicione suas chaves de API para ativar os serviços")

config = load_config()

# Formulário de configuração
with st. form("config_form"):
    st.subheader("🔑 Chaves de API")
    
    virustotal_key = st.text_input(
        "VirusTotal API Key",
        value=config.get('virustotal_api_key', ''),
        type="password",
        help="Obtenha em https://www.virustotal.com/gui/my-apikey"
    )
    
    abuseipdb_key = st.text_input(
        "AbuseIPDB API Key",
        value=config. get('abuseipdb_api_key', ''),
        type="password",
        help="Obtenha em https://www.abuseipdb.com/api"
    )
    
    shodan_key = st.text_input(
        "Shodan API Key",
        value=config.get('shodan_api_key', ''),
        type="password",
        help="Obtenha em https://shodan. io/account/api"
    )
    
    ipinfo_token = st.text_input(
        "IPinfo Token",
        value=config.get('ipinfo_token', ''),
        type="password",
        help="Obtenha em https://ipinfo.io/account/tokens"
    )
    
    greynoise_key = st.text_input(
        "GreyNoise API Key",
        value=config.get('greynoise_api_key', ''),
        type="password",
        help="Obtenha em https://www.greynoise.io/"
    )
    
    submitted = st.form_submit_button("💾 Salvar Configuração")
    
    if submitted:
        new_config = {
            'virustotal_api_key': virustotal_key,
            'abuseipdb_api_key': abuseipdb_key,
            'shodan_api_key': shodan_key,
            'ipinfo_token': ipinfo_token,
            'greynoise_api_key': greynoise_key,
        }
        save_config(new_config)
        st.success("✅ Configurações salvas com sucesso!")

# Testar APIs
st.markdown("---")
st.subheader("🧪 Testar APIs")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("Testar VirusTotal"):
        if config.get('virustotal_api_key'):
            try:
                headers = {"x-apikey": config['virustotal_api_key']}
                response = requests.get(
                    "https://www. virustotal.com/api/v3/ip_addresses/8.8.8.8",
                    headers=headers,
                    timeout=5
                )
                if response.status_code == 200:
                    st.success("✅ VirusTotal conectado!")
                else:
                    st.error(f"❌ Erro {response.status_code}")
            except Exception as e:
                st.error(f"❌ Erro: {str(e)}")
        else:
            st.warning("⚠️ API Key não configurada")

with col2:
    if st.button("Testar AbuseIPDB"):
        if config.get('abuseipdb_api_key'):
            try:
                headers = {"Key": config['abuseipdb_api_key']}
                response = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params={"ipAddress": "8.8.8.8"},
                    timeout=5
                )
                if response.status_code == 200:
                    st.success("✅ AbuseIPDB conectado!")
                else:
                    st. error(f"❌ Erro {response.status_code}")
            except Exception as e:
                st.error(f"❌ Erro: {str(e)}")
        else:
            st.warning("⚠️ API Key não configurada")

with col3:
    if st.button("Testar Shodan"):
        if config. get('shodan_api_key'):
            try:
                response = requests.get(
                    f"https://api.shodan. io/account/profile?key={config['shodan_api_key']}",
                    timeout=5
                )
                if response. status_code == 200:
                    st.success("✅ Shodan conectado!")
                else:
                    st. error(f"❌ Erro {response.status_code}")
            except Exception as e:
                st.error(f"❌ Erro: {str(e)}")
        else:
            st.warning("⚠️ API Key não configurada")