# Testes das heurísticas. Tudo com offline=True pra não depender de internet
# (senão o teste quebra toda vez que o WHOIS está de mau humor).

from detector import analisar, classificar, dominio_principal, nome_base


def risco(url):
    return analisar(url, offline=True)


def test_site_normal_fica_de_boa():
    r = risco("https://www.google.com")
    assert r["classificacao"] == "provavelmente seguro"
    assert r["pontuacao"] < 30


def test_ip_no_dominio_pontua_alto():
    r = risco("http://192.168.0.5/login")
    assert any("IP" in m for m in r["motivos"])
    assert r["pontuacao"] >= 40


def test_arroba_na_url():
    r = risco("http://banco.com@site-falso.xyz/")
    assert any("@" in m for m in r["motivos"])


def test_marca_fora_do_dominio_eh_phishing():
    r = risco("http://paypal.com.login-seguro.xyz/conta")
    assert r["classificacao"] == "provável phishing"
    assert any("paypal" in m for m in r["motivos"])


def test_tld_suspeito_soma_pontos():
    seguro = risco("https://exemplo.com")
    suspeito = risco("https://exemplo.tk")
    assert suspeito["pontuacao"] > seguro["pontuacao"]


def test_punycode():
    r = risco("http://xn--pypal-4ve.com/login")
    assert any("punycode" in m.lower() for m in r["motivos"])


def test_palavra_gatilho():
    r = risco("https://meusite.com/login/verificar/conta")
    assert any("isca" in m for m in r["motivos"])


def test_classificar_nas_faixas():
    assert classificar(0) == "provavelmente seguro"
    assert classificar(45) == "suspeito"
    assert classificar(85) == "provável phishing"


def test_dominio_principal_com_br():
    assert dominio_principal("internetbanking.bradesco.com.br") == "bradesco.com.br"
    assert nome_base("internetbanking.bradesco.com.br") == "bradesco"


def test_url_sem_http_ainda_funciona():
    r = risco("paypal.com.seguro-login.xyz/entrar")
    assert r["pontuacao"] > 0
