# The Operator - Plataforma de Inteligência de Ameaças

Plataforma integrada de análise de segurança com integração a múltiplas fontes de inteligência de ameaças.

## 🎨 Personalização do Logo

### Substituindo o Logo

O logo da aplicação está localizado em `assets/logo.svg`. Para personalizar com sua própria marca:

1. **Formato recomendado**: SVG (Scalable Vector Graphics)
   - Alternativamente, você pode usar PNG ou JPEG

2. **Dimensões recomendadas**:
   - Largura máxima: 200px
   - Altura máxima: 60px
   - O logo será redimensionado automaticamente para caber na sidebar

3. **Como substituir**:
   ```bash
   # Substitua o arquivo existente
   cp seu-logo.svg assets/logo.svg
   
   # Ou se estiver usando PNG
   cp seu-logo.png assets/logo.png
   # E atualize o arquivo styles/theme.py para apontar para .png
   ```

4. **Modificar o código** (se mudar o formato):
   - Edite `styles/theme.py`
   - Na função `get_sidebar_logo_html()`, altere a linha:
     ```python
     logo_path = Path(__file__).parent.parent / "assets" / "logo.svg"
     ```
     Para:
     ```python
     logo_path = Path(__file__).parent.parent / "assets" / "logo.png"
     ```

### Ajustando o Tamanho do Logo

Se precisar ajustar o tamanho do logo no sidebar, edite o arquivo `styles/theme.py`:

```python
# Localize a seção:
.sidebar-logo-container img {
    max-width: 100%;
    height: auto;
    max-height: 60px;  # Altere este valor
}
```

### Removendo o Logo

Para remover o logo completamente:

1. Edite `app.py` e remova a linha:
   ```python
   st.markdown(get_sidebar_logo_html(), unsafe_allow_html=True)
   ```

## 🎨 Personalização de Temas

### Cores e Estilos

Os estilos da aplicação estão centralizados em `styles/theme.py`. Para personalizar:

1. **Cores principais**:
   ```css
   background: #020617          /* Fundo escuro */
   color: #f9fafb              /* Texto principal */
   border: rgba(148, 163, 184, 0.35)  /* Bordas dos cards */
   ```

2. **Cards**:
   - Edite a classe `.card` em `get_common_styles()`
   - Modifique bordas, sombras, padding conforme necessário

3. **Status colors**:
   ```css
   .status-ok   { color: #22c55e; }  /* Verde */
   .status-warn { color: #facc15; }  /* Amarelo */
   .status-bad  { color: #fca5a5; }  /* Vermelho */
   ```

## 📦 Instalação

1. Clone o repositório:
   ```bash
   git clone https://github.com/guimunizzz/Analysis_Project.git
   cd Analysis_Project
   ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure suas chaves de API:
   - Acesse a página "Configurações" na aplicação
   - Ou crie um arquivo `.env` com suas chaves:
     ```
     VIRUSTOTAL_API_KEY=sua_chave_aqui
     ABUSEIPDB_API_KEY=sua_chave_aqui
     SHODAN_API_KEY=sua_chave_aqui
     IPINFO_TOKEN=sua_chave_aqui
     GREYNOISE_API_KEY=sua_chave_aqui
     IPQUALITYSCORE_API_KEY=sua_chave_aqui
     ```

4. Execute a aplicação:
   ```bash
   streamlit run app.py
   ```

## 🔧 Ferramentas Disponíveis

- **🔍 Análise de IP**: Verificar reputação de endereços IP em múltiplas fontes
- **🔗 Análise de Hash**: Validar hashes de arquivos (MD5, SHA1, SHA256)
- **🌐 Análise de Domínio**: Investigar domínios e URLs maliciosos
- **📋 Listas de Bloqueio**: Gerenciar IPs, hashes e domínios bloqueados
- **⚙️ Configurações**: Adicionar suas chaves de API para integração

## 🏗️ Estrutura do Projeto

```
Analysis_Project/
├── app.py                 # Página principal (Home)
├── pages/                 # Páginas da aplicação
│   ├── 1_🔍_IP_Analysis.py
│   ├── 2_🔗_Hash_Analysis.py
│   ├── 3_🌐_Domain_Analysis.py
│   ├── 4_📋_Blocklists.py
│   └── 5_⚙️_Settings.py
├── styles/                # Estilos centralizados
│   └── theme.py          # Tema e CSS comum
├── assets/                # Recursos visuais
│   └── logo.svg          # Logo da aplicação
├── config/                # Configurações
│   └── settings.py
├── services/              # Integrações com APIs
├── utils/                 # Utilitários
└── requirements.txt       # Dependências
```

## 📝 Licença

[Incluir informações de licença aqui]

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor, abra uma issue ou pull request.
