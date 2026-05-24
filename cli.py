"""
Linha de comando do detector.

Exemplos:
    python cli.py https://paypal.com.login-seguro.xyz/conta
    python cli.py --json site-suspeito.tk
"""

import argparse
import json
import sys

from detector import analisar


# Código de saída por classificação. Assim dá pra usar em script:
# 0 = de boa, 1 = suspeito, 2 = provável phishing.
CODIGOS = {
    "provavelmente seguro": 0,
    "suspeito": 1,
    "provável phishing": 2,
}


def montar_argumentos():
    parser = argparse.ArgumentParser(
        description="Analisa uma URL e diz se ela cheira a phishing."
    )
    parser.add_argument("url", help="a URL que você quer checar")
    parser.add_argument("--json", action="store_true",
                        help="mostra o resultado em JSON")
    return parser.parse_args()


def imprimir_bonito(resultado):
    print(f"URL:           {resultado['url']}")
    print(f"Classificação: {resultado['classificacao']}")
    print(f"Pontuação:     {resultado['pontuacao']}/100")
    if resultado["motivos"]:
        print("Motivos:")
        for motivo in resultado["motivos"]:
            print(f"  - {motivo}")
    else:
        print("Motivos:       nada de suspeito encontrado.")


def main():
    args = montar_argumentos()
    resultado = analisar(args.url)

    if args.json:
        print(json.dumps(resultado, ensure_ascii=False, indent=2))
    else:
        imprimir_bonito(resultado)

    sys.exit(CODIGOS.get(resultado["classificacao"], 0))


if __name__ == "__main__":
    main()
