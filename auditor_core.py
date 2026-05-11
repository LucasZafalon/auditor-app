"""
Audit Sentinel – Núcleo Profissional de Análise
Backend OSINT organizado, separador único, relatório legível, sugestões didáticas.
"""

import datetime
import socket
import ssl
import json
import time
import threading
import re
import hashlib
import requests
import dns.resolver
import os, sys

data_path = os.path.join(os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__), "public_suffix_list.dat")
os.environ['PUBLIC_SUFFIX_LIST_PATH'] = data_path

import whois
from OpenSSL import crypto
from bs4 import BeautifulSoup

try:
    import webtech
except ImportError:
    webtech = None

import config

HIBP_API = "https://haveibeenpwned.com/unifiedsearch/{}"
GRAVATAR_URL = "https://www.gravatar.com/avatar/{}?d=404"

_cache = {}
_cache_lock = threading.Lock()

def _get_cache(key):
    with _cache_lock:
        v = _cache.get(key)
        if v and time.time() - v[0] < config.CACHE_TTL:
            return v[1]
    return None

def _set_cache(key, value):
    with _cache_lock:
        _cache[key] = (time.time(), value)

def _cache_wrapper(func):
    def wrapper(*args, **kwargs):
        key = f"{func.__name__}:{str(args[0]).lower()}"
        cached_results = _get_cache(key)
        if cached_results:
            yield from cached_results
            return
        live_results = []
        for item in func(*args, **kwargs):
            live_results.append(item)
            yield item
        _set_cache(key, live_results)
    return wrapper

def create_separator(domain):
    width = 80
    padding = max(0, (width - len(domain) - 2) // 2)
    separator = f"{'=' * padding} {domain} {'=' * padding}"
    return separator + "=" * (width - len(separator))

def output_block(title, explanation, results, verdict="", suggestion=None, export_data=None):
    block = {
        "title": title,
        "explanation": explanation,
        "results": results,
        "verdict": verdict,
    }
    if suggestion:
        block['suggestion'] = suggestion
    if export_data:
        block['export_data'] = export_data
    return block

def handle_exception(module, e, domain, suggestion=None):
    msg = str(e)
    # Mensagem especial para erro do WebTech/config
    if module == "Tecnologias" and ("webtech.json" in msg or "No such file" in msg):
        msg = (
            "O módulo Webtech não encontrou o arquivo de configuração webtech.json. "
            "Para resolver: Rode 'webtech init' no terminal para criar o arquivo, "
            "ou reinstale o pacote via pip. Consulte a documentação do webtech para detalhes."
        )
    return output_block(
        title=f"[!] Falha em {module} para {domain}",
        explanation=f"Ocorreu um erro ao executar {module}.",
        results=[{"status": "bad", "text": msg}],
        verdict="VEREDITO: ERRO",
        suggestion=suggestion or "Revise a conexão de internet, DNS do domínio ou tente novamente mais tarde."
    )

def safe_dns_query(domain, r_type):
    try:
        return dns.resolver.resolve(domain, r_type, lifetime=config.NETWORK_TIMEOUT)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return None

def get_primary_ip(domain):
    answers = safe_dns_query(domain, 'A')
    return answers[0].to_text() if answers else None

def check_dnsbl(ip):
    results = []
    reversed_ip = '.'.join(reversed(ip.split('.')))
    for dnsbl in config.DNSBLs:
        try:
            query = f"{reversed_ip}.{dnsbl}"
            dns.resolver.resolve(query, 'A')
            results.append({"status": "bad", "text": f"IP listado na blacklist: {dnsbl}"})
        except dns.resolver.NXDOMAIN:
            results.append({"status": "good", "text": f"IP não listado em: {dnsbl}"})
        except Exception as ex:
            results.append({"status": "info", "text": f"Não foi possível consultar: {dnsbl} ({ex})"})
    return results

def brute_force_dirs(domain):
    found = []
    base_url = f"http://{domain}/"
    headers = {"User-Agent": config.USER_AGENT}
    for d in config.DIRS:
        url = base_url + d
        try:
            resp = requests.get(url, timeout=3, headers=headers)
            if resp.status_code in (200, 401, 403):
                found.append(url)
        except Exception:
            pass
    return found

def get_ssl_certificate(host, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=config.NETWORK_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(True)
                return crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
    except Exception:
        return None

def analyze_ssl(domain, export_data):
    cert = get_ssl_certificate(domain)
    if not cert:
        export_data['ssl_status'] = 'Erro'
        return output_block(
            "[+] SSL/TLS",
            "Análise do certificado SSL.",
            [{"status": "bad", "text": "Certificado SSL não encontrado ou conexão falhou."}],
            "VEREDITO: NÃO SEGURADO",
            suggestion="Verifique se o domínio utiliza HTTPS e o certificado está válido."
        )
    try:
        start = datetime.datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
        end = datetime.datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        issuer = cert.get_issuer().CN
        subject = cert.get_subject().CN
        now = datetime.datetime.utcnow()
        expired = now > end
        days_to_expire = (end - now).days
        results = [
            {"status": "info", "text": f"Emissor: {issuer}"},
            {"status": "info", "text": f"Sujeito: {subject}"},
            {"status": "good" if not expired else "bad", "text": f"Válido até: {end.strftime('%Y-%m-%d')} ({days_to_expire} dias)"}
        ]
        export_data['ssl_valid'] = not expired
        export_data['ssl_issuer'] = issuer
        export_data['ssl_expiry'] = end.strftime('%Y-%m-%d')
        suggestion = None
        if expired:
            suggestion = "Renove imediatamente o certificado SSL."
        elif days_to_expire < 30:
            suggestion = "O certificado expira em breve. Renove com antecedência!"
        return output_block(
            "[+] SSL/TLS",
            "Análise do certificado SSL.",
            results,
            "VEREDITO: OK" if not expired else "VEREDITO: EXPIRADO",
            suggestion=suggestion
        )
    except Exception as e:
        export_data['ssl_status'] = 'Erro'
        return handle_exception("SSL", e, domain)

def analyze_ptr(ip, domain, export_data):
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        match = domain in ptr
        export_data['ptr'] = ptr
        export_data['ptr_match'] = match
        return output_block(
            "[+] PTR (Reverso)",
            f"Validação do IP reverso do domínio ({ip}).",
            [{"status": "good" if match else "bad", "text": f"PTR: {ptr}"}],
            suggestion="Solicite ao provedor que configure o reverso para o domínio principal." if not match else None
        )
    except Exception as e:
        export_data['ptr'] = 'Erro'
        return handle_exception("PTR", e, domain)

def analyze_webtech(domain, export_data):
    if webtech is None:
        export_data['technologies'] = []
        return output_block(
            "[+] Tecnologias do Site",
            "Detecta frameworks e servidores via webtech.",
            [{"status": "info", "text": "webtech não instalado, não foi possível detectar tecnologias."}],
            suggestion="Instale a dependência opcional 'webtech' para esta funcionalidade."
        )
    try:
        scanner = webtech.WebTech(options={"json": True})
        report = scanner.start_from_url(f"http://{domain}")
        techs = [t['name'] for t in report.get('tech', [])]
        export_data['technologies'] = techs
        results = [{"status": "info", "text": ", ".join(techs) or "Nenhuma tecnologia detectada."}]
        return output_block(
            "[+] Tecnologias do Site",
            "Detecta frameworks, servidores, CDNs e scripts principais.",
            results
        )
    except Exception as e:
        return handle_exception("Tecnologias", e, domain)

def analyze_wayback(domain, export_data):
    try:
        resp = requests.get(config.WAYBACK_API.format(domain=domain), timeout=5)
        j = resp.json()
        if j.get("archived_snapshots"):
            available = j["archived_snapshots"].get("closest")
            if available:
                url = available.get("url")
                timestamp = available.get("timestamp")
                dt = datetime.datetime.strptime(timestamp, "%Y%m%d%H%M%S")
                export_data['wayback_url'] = url
                export_data['wayback_date'] = dt.strftime('%Y-%m-%d')
                return output_block(
                    "[+] Wayback Machine",
                    "Verifica presença de histórico do domínio na Wayback Machine.",
                    [{"status": "good", "text": f"Primeiro snapshot: {dt.strftime('%Y-%m-%d')} ({url})"}],
                    suggestion="Analise possíveis versões antigas para identificar vazamentos ou dados sensíveis."
                )
        export_data['wayback_url'] = None
        return output_block(
            "[+] Wayback Machine",
            "Verifica presença de histórico do domínio na Wayback Machine.",
            [{"status": "info", "text": "Nenhum snapshot encontrado."}]
        )
    except Exception as e:
        export_data['wayback_url'] = 'Erro'
        return handle_exception("Wayback", e, domain)

def process_whois_data(w, export_data):
    results = []
    now = datetime.datetime.utcnow()

    owner = getattr(w, 'owner', None) or getattr(w, 'org', None) or getattr(w, 'organization', 'N/A')
    tech_contact = getattr(w, 'tech_c', 'N/A')
    name_servers = getattr(w, 'name_servers', []) or []
    domain_status = getattr(w, 'status', []) or []

    def get_date(obj, key):
        val = getattr(obj, key, None)
        return val[0] if isinstance(val, list) else val

    creation_date = get_date(w, 'creation_date')
    updated_date = get_date(w, 'updated_date')
    expiration_date = get_date(w, 'expiration_date')

    results.append({'status': 'info', 'text': f"Titular: {owner}"})
    results.append({'status': 'info', 'text': f"Contato Técnico: {tech_contact}"})
    for ns in name_servers:
        results.append({'status': 'info', 'text': f"Servidor DNS: {ns}"})

    if creation_date:
        results.append({'status': 'info', 'text': f"Criado em: {creation_date.strftime('%Y-%m-%d')}"})
    if updated_date:
        results.append({'status': 'info', 'text': f"Alterado em: {updated_date.strftime('%Y-%m-%d')}"})
    if expiration_date:
        delta_expires = (expiration_date.replace(tzinfo=None) - now).days
        results.append({'status': 'bad' if delta_expires < config.EXPIRATION_ALERT_DAYS else 'good', 'text': f"Expira em: {expiration_date.strftime('%Y-%m-%d')} ({delta_expires} dias)"})

    status_str = ', '.join(map(str, domain_status)) if isinstance(domain_status, list) else str(domain_status)
    results.append({'status': 'info', 'text': f"Status: {status_str}"})

    domain_name_export = getattr(w, 'domain_name', None)
    export_data['domain'] = (domain_name_export[0] if isinstance(domain_name_export, list) else domain_name_export or "").lower()
    export_data['status'] = status_str
    export_data['expiration_date'] = expiration_date.strftime('%Y-%m-%d') if expiration_date else "N/A"
    export_data['name_servers'] = [str(ns) for ns in name_servers]
    export_data['tech_contact'] = str(tech_contact)
    export_data['owner'] = str(owner)
    return results

def harvest_emails(domain, export_data):
    emails_found = set()
    try:
        resp = requests.get(f"http://{domain}", timeout=5, headers={"User-Agent": config.USER_AGENT})
        soup = BeautifulSoup(resp.text, "html.parser")
        page_text = soup.get_text()
        emails = set(re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', page_text))
        emails_found.update(emails)
        export_data['public_emails'] = list(emails_found)
        return list(emails_found)
    except Exception:
        export_data['public_emails'] = []
        return []

def check_email_pwned(email):
    try:
        resp = requests.get(HIBP_API.format(email), headers={"User-Agent": config.USER_AGENT}, timeout=7)
        if resp.status_code == 200 and resp.json():
            return True
    except Exception:
        pass
    return False

def check_gravatar(email):
    try:
        hash_email = hashlib.md5(email.lower().encode()).hexdigest()
        resp = requests.get(GRAVATAR_URL.format(hash_email), timeout=5)
        return resp.status_code == 200
    except Exception:
        return False

def normalize_domain_list(domains_input):
    if isinstance(domains_input, list):
        return [d.strip().lower() for d in domains_input if d.strip()]
    return [d.strip().lower() for d in re.split(r"[\s,;]+", domains_input) if d.strip()]

# =========== ANALYSIS FUNCS ===========

@_cache_wrapper
def analyze_domain(domains_input, show_separator=True):
    domain_list = normalize_domain_list(domains_input)
    export_data_collector = []
    for domain in domain_list:
        export_data = {}
        if show_separator:
            yield {"title": create_separator(domain), "explanation": "", "results": [], "verdict": ""}
        ip = get_primary_ip(domain)
        dns_results = []
        for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            answers = safe_dns_query(domain, r_type)
            if answers is None:
                dns_results.append({'status': 'bad', 'text': f"Erro ao consultar {r_type}."})
                continue
            if not answers:
                dns_results.append({'status': 'alert', 'text': f"{r_type}: Nenhum registro encontrado."})
                continue
            for rdata in answers:
                dns_results.append({'status': 'good', 'text': f"{r_type}: {rdata.to_text()}"})
                export_data.setdefault(f"{r_type}_records", []).append(rdata.to_text())
        yield output_block(
            "[+] Registros DNS",
            "Consulta os principais registros de configuração do domínio.",
            dns_results,
            "VEREDITO: ANÁLISE CONCLUÍDA"
        )
        try:
            w = whois.whois(domain)
            if not w.domain_name:
                raise Exception("Informação de WHOIS não encontrada ou protegida.")
            display_results = process_whois_data(w, export_data)
            yield output_block(
                "[+] Análise de WHOIS",
                "Verifica as informações de registro público.",
                display_results,
                "VEREDITO: ANÁLISE CONCLUÍDA"
            )
        except Exception as e:
            yield handle_exception("WHOIS", e, domain)
        yield analyze_ssl(domain, export_data)
        if ip:
            yield analyze_ptr(ip, domain, export_data)
            dnsbl_results = check_dnsbl(ip)
            export_data['dnsbl'] = dnsbl_results
            yield output_block(
                "[+] Blacklists DNSBL",
                "Consulta reputação do IP em blacklists de SPAM conhecidas.",
                dnsbl_results,
                suggestion="Se listado, peça remoção nos sites das listas."
            )
        yield analyze_webtech(domain, export_data)
        dirs_found = brute_force_dirs(domain)
        export_data['sensitive_dirs'] = dirs_found
        yield output_block(
            "[+] Diretórios comuns encontrados",
            "Busca por caminhos administrativos ou sensíveis.",
            [{"status": "good", "text": url} for url in dirs_found] or [{"status": "info", "text": "Nenhum diretório sensível encontrado."}],
            suggestion="Proteja esses diretórios com autenticação forte e ocultação."
        )
        yield analyze_wayback(domain, export_data)
        emails_found = harvest_emails(domain, export_data)
        if emails_found:
            yield output_block(
                "[+] E-mails públicos encontrados",
                "E-mails expostos em páginas públicas do site.",
                [{"status": "alert", "text": e} for e in emails_found],
                suggestion="Evite exposição pública de e-mails sensíveis."
            )
        export_data_collector.append(export_data)
    yield {'export_data': export_data_collector}

@_cache_wrapper
def analyze_email(domains_input, show_separator=True):
    domain_list = normalize_domain_list(domains_input)
    export_data_collector = []
    for item in domain_list:
        export_data = {}
        if "@" in item:
            email = item.strip().lower()
            if show_separator:
                yield {"title": create_separator(email), "explanation": "", "results": [], "verdict": ""}
            pwned = check_email_pwned(email)
            export_data['hibp_pwned'] = pwned
            hibp_results = [{"status": "alert" if pwned else "good",
                             "text": "Encontrado em vazamentos públicos!" if pwned else "Não encontrado em vazamentos públicos."}]
            yield output_block(
                "[+] Vazamentos de Dados (HaveIBeenPwned)",
                "Consulta de exposição do e-mail em vazamentos públicos.",
                hibp_results,
                suggestion="Troque a senha se estiver exposto." if pwned else None
            )
            gravatar_exists = check_gravatar(email)
            export_data['gravatar_profile'] = gravatar_exists
            gravatar_results = [{"status": "good" if gravatar_exists else "info",
                                 "text": "Perfil público encontrado no Gravatar." if gravatar_exists else "Nenhum perfil Gravatar encontrado."}]
            yield output_block(
                "[+] Gravatar",
                "Verifica perfil público vinculado ao e-mail.",
                gravatar_results
            )
            yield output_block(
                "[!] Limitação de Análise",
                "",
                [{"status": "info",
                  "text": "A análise de segurança de e-mails via OSINT verifica apenas exposição pública do endereço em vazamentos. Não é possível verificar tentativas de acesso indevido, pois isso exigiria acesso ao servidor de e-mail."}]
            )
            export_data_collector.append(export_data)
        else:
            domain = item
            if show_separator:
                yield {"title": create_separator(domain), "explanation": "", "results": [], "verdict": ""}
            mx_records_raw = safe_dns_query(domain, 'MX')
            if mx_records_raw is None:
                yield output_block(
                    "[+] Registros MX",
                    "Verifica os servidores responsáveis por receber e-mails.",
                    [{'status': 'bad', 'text': 'Erro ao consultar registros MX.'}],
                    "VEREDITO: ERRO"
                )
                mx_hosts = []
            else:
                mx_hosts = sorted(mx_records_raw, key=lambda r: r.preference)
                export_data['mx_records'] = [r.to_text() for r in mx_hosts]
                yield output_block(
                    "[+] Registros MX",
                    "Verifica os servidores responsáveis por receber e-mails.",
                    [{'status': 'good', 'text': f"MX: {r.to_text()}"} for r in mx_hosts] if mx_hosts else [{'status':'bad', 'text': 'Nenhum registro MX encontrado.'}],
                    "VEREDITO: OK" if mx_hosts else "VEREDITO: FALHA CRÍTICA"
                )
            txt_records = safe_dns_query(domain, 'TXT')
            if txt_records is None:
                yield output_block(
                    "[+] Análise de Registro SPF",
                    "Verifica a política de autorização de envio de e-mails.",
                    [{'status':'bad', 'text':'Erro ao consultar registros TXT.'}],
                    "VEREDITO: ERRO"
                )
            else:
                spf_record = next((str(r) for r in txt_records if 'v=spf1' in str(r).lower()), None)
                export_data['spf_record'] = spf_record
                spf_results = []
                verdict = ""
                suggestion = None
                if spf_record:
                    spf_results.append({'status': 'info', 'text': spf_record})
                    if '+all' in spf_record:
                        spf_results.append({'status': 'bad', 'text': 'Risco alto: A política "+all" permite spoofing.'})
                        verdict = "FALHA DE SEGURANÇA"
                        suggestion = "Substitua '+all' por '-all' para proteger o domínio."
                    elif '~all' in spf_record:
                        spf_results.append({'status': 'alert', 'text': 'Alerta: A política "~all" (SoftFail) é permissiva.'})
                        verdict = "AÇÃO RECOMENDADA"
                        suggestion = "Prefira usar '-all' para melhor proteção."
                    elif '-all' in spf_record:
                        spf_results.append({'status': 'good', 'text': 'Boa prática: A política "-all" (Fail) está correta.'})
                        verdict = "CONFIGURAÇÃO SEGURA"
                else:
                    spf_results.append({'status': 'bad', 'text': 'Nenhum registro SPF encontrado.'})
                    verdict = "FALHA CRÍTICA"
                    suggestion = "Crie um registro SPF para evitar spoofing de e-mails."
                yield output_block(
                    "[+] Análise de Registro SPF",
                    "Verifica a política de autorização de envio de e-mails.",
                    spf_results,
                    f"VEREDITO: {verdict}",
                    suggestion
                )
            for check, name in [('default._domainkey', 'DKIM'), ('_dmarc', 'DMARC')]:
                q_name = f"{check}.{domain}"
                records = safe_dns_query(q_name, 'TXT')
                found = any(r is not None for r in records)
                export_data[f"{name.lower()}_found"] = found
                results, verdict = [], ""
                if records is None:
                    results = [{'status': 'bad', 'text': f'Erro ao consultar registro {name}.'}]
                    verdict = "ERRO"
                else:
                    results = [{'status': 'good' if found else 'bad', 'text': f'Registro {name} {"encontrado." if found else "não encontrado."}'}]
                    verdict = 'OK' if found else 'AÇÃO RECOMENDADA'
                suggestion = None if found else f"Implemente o registro {name} para aumentar a segurança."
                yield output_block(
                    f"[+] Análise de Registro {name}",
                    f"Verifica a existência do registro de segurança {name}.",
                    results,
                    f"VEREDITO: {verdict}",
                    suggestion
                )
            emails_found = harvest_emails(domain, export_data)
            if emails_found:
                yield output_block(
                    "[+] E-mails públicos encontrados",
                    "E-mails expostos em páginas públicas do site.",
                    [{"status": "alert", "text": e} for e in emails_found],
                    suggestion="Evite exposição pública de e-mails sensíveis."
                )
            export_data_collector.append(export_data)
    yield {'export_data': export_data_collector}

@_cache_wrapper
def analyze_osint(domains_input):
    domain_list = normalize_domain_list(domains_input)
    export_data_collector = []
    for domain in domain_list:
        export_data = {}
        # Separador só aqui!
        yield {"title": create_separator(domain), "explanation": "", "results": [], "verdict": ""}
        # Passa show_separator=False para evitar separador duplicado
        for block in analyze_domain(domain, show_separator=False):
            if 'export_data' in block:
                continue
            yield block
        for block in analyze_email(domain, show_separator=False):
            if 'export_data' in block:
                continue
            yield block
        try:
            r = requests.get(config.CRT_API.format(domain=domain), timeout=config.NETWORK_TIMEOUT, headers={'User-Agent': config.USER_AGENT})
            r.raise_for_status()
            subs = sorted({j["name_value"] for j in r.json() if j["name_value"].endswith(f".{domain}") and not j["name_value"].startswith('*')})
            results = [{'status': 'good', 'text': s} for s in subs]
            verdict = f"{len(subs)} encontrados."
            export_data['subdomains'] = subs
        except Exception as e:
            results = [{'status': 'bad', 'text': f'Falha na consulta: {str(e)}'}]
            verdict = "ERRO NA CONSULTA"
            export_data['subdomains'] = []
        yield output_block(
            '[+] Subdomínios (crt.sh)',
            'Busca por subdomínios registrados em certificados SSL.',
            results if results else [{'status': 'info', 'text': 'Nenhum subdomínio público encontrado.'}],
            f'VEREDITO: {verdict}'
        )
        export_data_collector.append(export_data)
    yield {'export_data': export_data_collector}

@_cache_wrapper
def analyze_whois_bulk(domains_input):
    domain_list = normalize_domain_list(domains_input)
    export_data_collector = []
    for domain in domain_list:
        export_data = {}
        yield {"title": create_separator(domain), "explanation": "", "results": [], "verdict": ""}
        try:
            w = whois.whois(domain)
            if not w.domain_name:
                raise Exception("Informação de WHOIS não encontrada ou protegida.")
            display_results = process_whois_data(w, export_data)
            yield output_block(
                f'[!] Análise de WHOIS para {domain}',
                'Verifica as informações de registro público do domínio.',
                display_results,
                'VEREDITO: ANÁLISE CONCLUÍDA'
            )
            export_data_collector.append(export_data)
        except Exception as e:
            yield handle_exception("WHOIS", e, domain)
            export_data_collector.append({"domain": domain, "status": "Erro"})
    yield {'export_data': export_data_collector}
