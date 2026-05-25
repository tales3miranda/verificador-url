"""
Detector de phishing baseado na análise da URL.

A ideia é simples: cada característica suspeita da URL soma alguns pontos.
No fim a gente olha o total e decide se a coisa cheira a golpe ou não.
As checagens que dependem de internet (DNS, WHOIS, redirecionamento) ficam
no módulo verificacoes_online e só rodam quando 'offline' é False.
"""

import ipaddress
from urllib.parse import urlparse


# Quanto cada sinal "pesa" no total. Deixei tudo junto aqui pra ficar fácil
# de calibrar depois sem ter que caçar número espalhado pelo código.
PESOS = {
    "ip_no_dominio": 40,
    "arroba_na_url": 25,
    "tld_no_subdominio": 20,
    "muitos_subdominios": 15,
    "muitos_hifens": 10,
    "url_muito_longa": 10,
    "dominio_com_marca_e_hifen": 20,
    "tld_suspeito": 20,
    "palavra_gatilho": 10,
    "marca_fora_do_dominio": 30,
    "punycode": 25,
    "porta_fora_do_padrao": 15,
    # daqui pra baixo só rola com internet
    "dns_nao_resolve": 30,
    "dominio_recem_criado": 30,
    "dominio_meio_novo": 15,
    "redireciona_pra_outro_dominio": 20,
}

# Palavras que phishing adora colocar na URL pra dar aquele ar de "oficial".
GATILHOS = [
    "login", "entrar", "conta", "senha", "verificar", "verificacao",
    "seguro", "seguranca", "atualizar", "confirmar", "banco", "cartao",
    "premio", "desbloquear", "suspenso", "recadastro", "fatura", "cliente",
]

# Marcas que costumam ser imitadas. Se o nome aparece mas o domínio é outro,
# quase sempre é tentativa de se passar por elas.
MARCAS = [
    "paypal", "google", "apple", "microsoft", "facebook", "instagram",
    "whatsapp", "netflix", "amazon", "mercadolivre", "mercadopago",
    "nubank", "itau", "bradesco", "santander", "caixa", "bancodobrasil",
    "correios", "steam", "binance", "outlook", "icloud",
]

# TLDs baratos/gratuitos que aparecem muito em golpe.
TLDS_SUSPEITOS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work",
    "click", "link", "country", "loan", "review", "fit", "gdn", "rest",
    "cam", "sbs",
}

# TLDs de verdade que, quando aparecem como subdomínio, denunciam o truque
# do tipo "paypal.com.site-falso.xyz".
TLDS_DE_VERDADE = {"com", "net", "org", "gov", "edu", "co", "io"}

# Alguns TLDs compostos pra não tratar "bradesco.com.br" como se o domínio
# fosse só "com.br".
# TODO: um dia trocar essa gambiarra por uma lib de TLD de verdade (tldextract).
TLDS_COMPOSTOS = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.uk", "com.au", "co.jp",
}


def dominio_principal(host):
    # Devolve o domínio "registrável", tipo google.com ou bradesco.com.br.
    partes = host.split(".")
    if len(partes) <= 2:
        return host
    if ".".join(partes[-2:]) in TLDS_COMPOSTOS:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])


def nome_base(host):
    # Só o nome, sem o TLD. Pra "login-seguro.xyz" devolve "login-seguro".
    return dominio_principal(host).split(".")[0]


def subdominios(host):
    principal = dominio_principal(host)
    prefixo = host[: len(host) - len(principal)].rstrip(".")
    if not prefixo:
        return []
    return prefixo.split(".")


def eh_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def classificar(pontuacao):
    if pontuacao >= 70:
        return "provável phishing"
    if pontuacao >= 30:
        return "suspeito"
    return "provavelmente seguro"


def analisar(url, offline=False, timeout=5):
    """
    Analisa uma URL e devolve um dicionário com a pontuação de risco (0 a 100),
    a classificação e a lista de motivos que levaram àquela nota.

    offline=True pula tudo que depende de internet (útil pra testar ou pra
    rodar em lugar sem rede).
    """
    url = url.strip()
    dados = urlparse(url)
    if not dados.scheme:
        # muita gente cola "site.com/login" sem o http na frente
        dados = urlparse("http://" + url)

    host = (dados.hostname or "").lower()
    caminho = (dados.path or "").lower()

    if not host:
        return {
            "url": url,
            "pontuacao": 0,
            "classificacao": "provavelmente seguro",
            "motivos": ["Não consegui identificar um domínio nessa URL."],
        }

    pontuacao = 0
    motivos = []
    eh_endereco_ip = eh_ip(host)

    if eh_endereco_ip:
        pontuacao += PESOS["ip_no_dominio"]
        motivos.append(f"Usa um IP no lugar de um domínio ({host}).")

    if dados.username:
        # o velho truque do http://banco.com@site-falso.com
        pontuacao += PESOS["arroba_na_url"]
        motivos.append("Tem um '@' na URL, que pode esconder o destino real.")

    if len(url) > 75:
        pontuacao += PESOS["url_muito_longa"]
        motivos.append(f"URL longa demais ({len(url)} caracteres).")

    achadas = [palavra for palavra in GATILHOS if palavra in host or palavra in caminho]
    if achadas:
        pontuacao += PESOS["palavra_gatilho"]
        motivos.append("Tem palavra de isca na URL: " + ", ".join(achadas) + ".")

    if "xn--" in host:
        pontuacao += PESOS["punycode"]
        motivos.append("Domínio em punycode (xn--), usado pra imitar letras de marcas.")

    try:
        porta = dados.port
    except ValueError:
        porta = None
    if porta not in (None, 80, 443):
        pontuacao += PESOS["porta_fora_do_padrao"]
        motivos.append(f"Acessa por uma porta fora do padrão ({porta}).")

    # As checagens abaixo só fazem sentido quando o host é um domínio mesmo,
    # e não um IP.
    if not eh_endereco_ip:
        subs = subdominios(host)
        subs_uteis = [s for s in subs if s != "www"]
        base = nome_base(host)

        if any(s in TLDS_DE_VERDADE for s in subs):
            pontuacao += PESOS["tld_no_subdominio"]
            motivos.append("Enfia algo tipo '.com' no subdomínio pra enganar.")

        if len(subs_uteis) >= 2:
            pontuacao += PESOS["muitos_subdominios"]
            motivos.append(f"Tem subdomínios demais ({'.'.join(subs)}).")

        if base.count("-") >= 2:
            pontuacao += PESOS["muitos_hifens"]
            motivos.append("O domínio tem muitos hífens, coisa que site sério evita.")

        marca_no_base = ""
        for marca in MARCAS:
            if marca in base and marca != base:
                marca_no_base = marca
                break
        if "-" in base and marca_no_base:
            pontuacao += PESOS["dominio_com_marca_e_hifen"]
            motivos.append(f"Mistura a marca '{marca_no_base}' com hífen no domínio.")

        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in TLDS_SUSPEITOS:
            pontuacao += PESOS["tld_suspeito"]
            motivos.append(f"Termina em '.{tld}', extensão bem comum em golpe.")

        texto_sub = ".".join(subs)
        marca_intrusa = ""
        for marca in MARCAS:
            if (marca in texto_sub or marca in caminho) and marca != base:
                marca_intrusa = marca
                break
        if marca_intrusa:
            pontuacao += PESOS["marca_fora_do_dominio"]
            motivos.append(
                f"Cita a marca '{marca_intrusa}', mas o domínio de verdade é "
                f"'{dominio_principal(host)}'."
            )

    if not offline:
        extra, mais_motivos = _checar_online(url, host, timeout)
        pontuacao += extra
        motivos += mais_motivos

    pontuacao = min(pontuacao, 100)
    return {
        "url": url,
        "pontuacao": pontuacao,
        "classificacao": classificar(pontuacao),
        "motivos": motivos,
    }


def _checar_online(url, host, timeout):
    # Importo aqui dentro de propósito: assim quem só quer a análise do texto
    # da URL consegue usar o detector sem instalar requests/python-whois.
    from verificacoes_online import resolve_dns, idade_em_dias, destino_final

    if not resolve_dns(host, timeout):
        return PESOS["dns_nao_resolve"], ["O domínio não resolve no DNS (talvez nem exista)."]

    pontos = 0
    motivos = []

    idade = idade_em_dias(host)
    if idade is not None and idade < 30:
        pontos += PESOS["dominio_recem_criado"]
        motivos.append(f"Domínio criado faz só {idade} dias — recém-nascido é bandeira vermelha.")
    elif idade is not None and idade < 90:
        pontos += PESOS["dominio_meio_novo"]
        motivos.append(f"Domínio ainda novo, com {idade} dias de vida.")

    destino = destino_final(url, timeout)
    if destino:
        host_final = (urlparse(destino).hostname or "").lower()
        if host_final and host_final != host:
            pontos += PESOS["redireciona_pra_outro_dominio"]
            motivos.append(f"Redireciona pra outro domínio: {host_final}")

    return pontos, motivos
