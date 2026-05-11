# Audit Sentinel v2.0 – OSINT & Domain Auditor

O **Audit Sentinel** é uma ferramenta profissional de auditoria e coleta de informações (OSINT) desenvolvida em Python. Projetada para analistas de segurança e administradores de sistemas, a aplicação realiza diagnósticos profundos em domínios e e-mails, consolidando dados técnicos em uma interface gráfica moderna e intuitiva.

## 🚀 Funcionalidades Principais

A ferramenta está dividida em quatro módulos principais de análise:

### 1. Análise Completa (OSINT)

* **Subdomínios:** Descoberta via `crt.sh` através de certificados SSL públicos.
* **Wayback Machine:** Identificação de snapshots históricos para encontrar arquivos ou diretórios antigos expostos.
* **Webtech:** Detecção de tecnologias de backend, frameworks, CMS e servidores.
* **Diretórios Sensíveis:** Brute-force rápido em caminhos administrativos comuns.

### 2. Diagnóstico de Domínio e Infraestrutura

* **DNS:** Consulta detalhada de registros A, AAAA, MX, NS e TXT.
* **Certificado SSL/TLS:** Validação de emissor, sujeito e data de expiração com alertas de renovação.
* **Reputação IP (DNSBL):** Verificação de presença em blacklists de SPAM globais.
* **PTR (Reverso):** Validação de conformidade do IP reverso com o domínio.

### 3. Auditoria de E-mail e Segurança de Mensageria

* **Políticas de Envio:** Análise técnica de registros **SPF** (incluindo detecção de riscos como `+all`), **DKIM** e **DMARC**.
* **Harvesting:** Extração automática de e-mails públicos em páginas do domínio.
* **Vazamentos (HIBP):** Integração para verificar se e-mails foram expostos em data breaches públicos.
* **Identidade:** Verificação de perfis públicos vinculados via Gravatar.

### 4. Análise de WHOIS em Massa

* Consulta simplificada de titularidade, data de criação e expiração para múltiplos alvos simultaneamente.

## 🛠️ Tecnologias Utilizadas

* **Linguagem:** Python 3.x
* **Interface Gráfica:** PySide6 (Qt para Python)
* **Principais Bibliotecas:** * `dnspython` para resolução de nomes.
* `python-whois` para dados de registro.
* `pyOpenSSL` para inspeção de certificados.
* `BeautifulSoup4` para web scraping e harvesting.
* `requests` para consumo de APIs (HIBP, Wayback, crt.sh).



## 📦 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/auditor-app.git
cd auditor-app

```


2. Instale as dependências:
```bash
pip install -r requirements.txt

```


*Nota: Recomenda-se o uso de um ambiente virtual (venv).*
3. Inicialize o banco de dados do Webtech (opcional para detecção de tecnologias):
```bash
webtech --urls http://example.com

```



## 🖥️ Como Usar

Para iniciar a interface gráfica:

```bash
python main_gui.py

```

* **Input:** Insira os domínios ou e-mails no campo de texto (separados por vírgula ou nova linha).
* **Exportação:** Após a análise, você pode exportar os resultados completos em formato **CSV** ou **JSON** para relatórios externos.

## 🛡️ Segurança e Ética

Esta ferramenta foi desenvolvida para fins educacionais e auditorias de segurança autorizadas. O uso para coleta de dados sem permissão pode violar termos de serviço de terceiros ou legislações locais.

---

**Desenvolvido por:** [Lucas Zafalon](https://github.com/LucasZafalon)

---
