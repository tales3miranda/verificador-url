"""
As checagens do detector que dependem de internet.

Tudo aqui é "best effort": se a rede cair, o WHOIS engasgar ou o site não
responder, a gente simplesmente devolve None/False em vez de explodir. Quem
chama trata isso como "não deu pra confirmar" e segue a vida.
"""

import socket
from datetime import datetime

import requests
import whois


# Alguns sites bloqueiam quem não manda um User-Agent de navegador.
CABECALHOS = {
    "User-Agent": "Mozilla/5.0 (compatible; verificador-de-url/1.0)"
}


def resolve_dns(host, timeout=5):
    socket.setdefaulttimeout(timeout)
    try:
        socket.gethostbyname(host)
        return True
    except OSError:
        return False
    finally:
        socket.setdefaulttimeout(None)


def idade_em_dias(host):
    # O whois falha bastante dependendo do TLD e do registrador, então se der
    # qualquer ruim a gente só desiste e devolve None.
    # TODO: dava pra cachear isso pra não consultar o mesmo domínio toda hora.
    try:
        dados = whois.whois(host)
    except Exception:
        return None

    criacao = dados.creation_date
    if isinstance(criacao, list):
        criacao = criacao[0] if criacao else None
    if not isinstance(criacao, datetime):
        return None

    criacao = criacao.replace(tzinfo=None)  # tira o fuso pra não dar treta na subtração
    return (datetime.now() - criacao).days


def destino_final(url, timeout=5):
    # Segue os redirecionamentos e diz onde a URL realmente vai parar.
    try:
        resposta = requests.get(url, headers=CABECALHOS, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None
    return resposta.url
