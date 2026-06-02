# verificador-url

Um detector de phishing que olha pra **URL** e tenta dizer se ela é confiável ou se cheira a golpe. Não é mágica nem IA — é um monte de regra baseada nas manhas que sites de phishing costumam usar (IP no lugar do domínio, marca famosa no subdomínio errado, domínio registrado ontem, etc). Cada sinal suspeito soma pontos e, no fim, a URL recebe uma nota de 0 a 100.

A intenção era ter uma ferramenta simples de entender e fácil de ajustar: dá pra ler o código e saber exatamente por que uma URL foi marcada.

## Como funciona

São dois grupos de checagem.

**1. Em cima do texto da URL** (sempre roda, não precisa de internet):

- IP no lugar do domínio
- `@` na URL, que esconde o destino real
- ".com" enfiado no subdomínio (`paypal.com.site-falso.xyz`)
- subdomínios e hífens demais
- TLD barato/grátis muito usado em golpe (`.tk`, `.xyz`, `.zip`...)
- palavras-isca (`login`, `verificar`, `conta`, `senha`...)
- marca famosa fora do domínio de verdade
- punycode (`xn--`, usado pra imitar letras)
- porta fora do padrão

**2. Checagens online** (precisa de internet, dá pra desligar com `--offline`):

- o domínio resolve no DNS?
- há quanto tempo o domínio existe (WHOIS) — recém-criado é bandeira vermelha
- pra onde a URL realmente redireciona

## Instalação

```
pip install -r requirements.txt
```

As checagens só de texto funcionam sem instalar nada; os pacotes (`requests` e `python-whois`) são só pro modo online.

## Uso

Na linha de comando:

```
python cli.py https://paypal.com.login-seguro.xyz/conta
python cli.py --offline exemplo.com
python cli.py --json site-suspeito.tk
```

Saída de exemplo:

```
URL:           http://paypal.com.login-seguro.xyz/conta
Classificação: provável phishing
Pontuação:     95/100
Motivos:
  - Enfia algo tipo '.com' no subdomínio pra enganar.
  - Tem subdomínios demais (paypal.com).
  - Termina em '.xyz', extensão bem comum em golpe.
  - Tem palavra de isca na URL: login, conta.
  - Cita a marca 'paypal', mas o domínio de verdade é 'login-seguro.xyz'.
```

Como módulo, no seu próprio código:

```python
from detector import analisar

resultado = analisar("http://site-falso.tk/login", offline=True)
print(resultado["classificacao"], resultado["pontuacao"])
for motivo in resultado["motivos"]:
    print("-", motivo)
```

## Ajustando os pesos

Todos os pesos ficam no dicionário `PESOS`, lá no começo do `detector.py`. Quer deixar mais ou menos rígido? É só mexer nos números. As listas de marcas, palavras-isca e TLDs suspeitos estão logo abaixo, fáceis de aumentar.

## Rodando os testes

```
pip install pytest
pytest
```

Os testes rodam todos em modo offline, então não dependem de internet.

## Limitações (importante)

- Isso **não substitui** antivírus, navegador atualizado nem bom senso. É um indicador, não uma sentença.
- A separação de domínio (`.com.br` e cia) é simplificada — trato só alguns TLDs compostos na mão.
- O WHOIS falha bastante dependendo do registrador; quando falha, a checagem de idade é simplesmente ignorada.
- Pode dar falso positivo (site de verdade com URL estranha) e falso negativo (golpe bem-feito). Use como mais uma camada, não como verdade absoluta.

## Por que regras e não machine learning?

Porque dá pra ler e entender cada decisão. Um modelo de ML seria uma caixa-preta dizendo "70% phishing" sem explicar o porquê. Aqui a ferramenta te diz exatamente quais sinais levantaram a suspeita — e, pra um detector desse tipo, isso vale mais do que alguns pontos de acurácia.
