"""
Arquivo de configuração global do Audit Sentinel.
Centraliza parâmetros de rede, listas para brute-force, blacklists, timeouts, APIs e regras de negócio.
Tudo pode ser facilmente ajustado para novas necessidades do projeto.
"""

# ===============================================
# CONFIGURAÇÕES DE REDE E PORTAS PARA ESCANEAMENTO
# ===============================================

PORTS_OSINT = [80, 443, 22, 21, 3306, 8080]    # Portas comuns para análise OSINT
PORTS_EMAIL = [25, 465, 587, 143, 993]         # Portas típicas de e-mail (SMTP, IMAP, etc)

# ===============================================
# DIRETÓRIOS COMUNS PARA BRUTE-FORCE DE PÁGINAS
# ===============================================

DIRS = [
    "admin", "login", "wp-admin", "panel", "dashboard", "backup", "api", 
    "test", "private", "portal", "config", "old", "secure", "public",
    "wp-login.php", "admin.php", "administrator", "json"
]

# ===============================================
# LISTA DE DNS BLACKLISTS (REPUTAÇÃO)
# ===============================================

DNSBLs = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org"
]

# ===============================================
# CONFIGURAÇÕES GERAIS E APIS EXTERNAS
# ===============================================

CACHE_TTL = 300   # Tempo de vida do cache em segundos (default: 5 minutos)
WAYBACK_API = "https://archive.org/wayback/available?url={domain}"
CRT_API = "https://crt.sh/?q=%.{domain}&output=json"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/91.0.4472.124 Safari/537.36"
)
NETWORK_TIMEOUT = 10  # Timeout padrão para requisições de rede em segundos

# ===============================================
# REGRAS DE NEGÓCIO PARA ANÁLISE WHOIS
# ===============================================

WHOIS_TECH_CONTACT = "ISSEM"  # Valor que, se presente, sinaliza bom contato técnico
WHOIS_NS_LIST_VALID = [
    "ns1.tiideal.com.br", 
    "ns2.tiideal.com.br",
    "ns3.meusitecontabil.com.br",
    "ns4.meusitecontabil.com.br"
]
EXPIRATION_ALERT_DAYS = 30    # Alerta de expiração próxima (em dias)
CHANGED_ALERT_DAYS = 30       # Alerta de alteração recente (em dias)
CREATION_ALERT_DAYS = 30      # Alerta de domínio criado recentemente (em dias)
