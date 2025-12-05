# Sec Analysis 

Plataforma de inteligência de ameaças construída com Streamlit, oferecendo análise de IPs, hashes e domínios com integração a diversas fontes (VirusTotal, AbuseIPDB, Shodan, IPinfo, GreyNoise, IPQualityScore).

## � Principais recursos

- Análise de reputação de IP em múltiplas APIs
- Verificação de hashes (MD5, SHA1, SHA256)
- Investigação de domínios/URLs
- Gerenciamento de listas de bloqueio (IPs, hashes, domínios)
- Tema escuro moderno com UI consistente
- Configuração centralizada de chaves de API

## 🏗️ Arquitetura

- `app.py`: Página inicial com UI e métricas
- `pages/`: Páginas modulares da aplicação (IP, Hash, Domínio, Blocklists, Configurações)
- `services/`: Integrações com provedores (VirusTotal, AbuseIPDB, Shodan, etc.)
- `styles/theme.py`: Tema central e CSS comum (inclui logo na sidebar)
- `config/settings.py`: Carregamento e persistência de configuração (.env e JSON)
- `utils/`: Validadores, formatadores e parsers

## � Instalação e execução

1) Clone e entre no projeto

```powershell
git clone https://github.com/guimunizzz/Analysis_Project.git
cd Analysis_Project
```

2) Crie o ambiente e instale dependências

```powershell
pip install -r requirements.txt
```

3) Configure suas chaves de API (opções)

- Pela interface: abra a página "⚙️ Configurações" e preencha as chaves
- Ou via `.env` na raiz do projeto:

```text
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
SHODAN_API_KEY=...
IPINFO_TOKEN=...
GREYNOISE_API_KEY=...
IPQUALITYSCORE_API_KEY=...
```

4) Execute a aplicação

```powershell
streamlit run app.py
```

## 🧩 Páginas

- `1_🔍_IP_Analysis.py`: Consulta reputação e detalhes de IP
- `2_🔗_Hash_Analysis.py`: Busca informações para hashes MD5/SHA1/SHA256
- `3_🌐_Domain_Analysis.py`: Avalia domínios e possíveis indicadores
- `4_📋_Blocklists.py`: Administra listas de bloqueio locais
- `5_⚙️_Settings.py`: Configura suas chaves de API e testa conectividade


## 🔌 Serviços integrados

- VirusTotal (`services/virustotal.py`)
- AbuseIPDB (`services/abuseipdb.py`)
- Shodan (`services/shodan.py`)
- IPinfo (`services/ipinfo.py`)
- GreyNoise (`services/greynoise.py`)
- IPQualityScore (`services/ipqualityscore.py`)

## ❗ Observações importantes

- O arquivo de configuração é persistido em `data/config.json` (gerado automaticamente)
- Variáveis de ambiente via `.env` são carregadas com `python-dotenv`
- Em ambientes Windows PowerShell, use os comandos acima exatamente como mostrados

## 🛠️ Troubleshooting

- Logo não aparece ou quebra:
  - Verifique se o arquivo está em `assets` e use um dos nomes suportados
  - Formatos aceitos: SVG, PNG, JPG/JPEG, WEBP
- Erros ao testar APIs em "Configurações":
  - Confirme chaves válidas e conectividade de rede
  - Consulte os serviços correspondentes em `services/`


## 🤝 Contribuição

Contribuições são bem-vindas! Abra uma issue ou envie um pull request.
