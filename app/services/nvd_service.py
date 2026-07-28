import requests
from datetime import datetime

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

ultima_atualizacao = None


def consultar_vulnerabilidades(fabricante, produto, versao):
    global ultima_atualizacao

    keyword = f"{fabricante} {produto} {versao}"

    resposta = requests.get(
        BASE_URL,
        params={
            "keywordSearch": keyword,
            "resultsPerPage": 20
        },
        timeout=30
    )

    if resposta.status_code == 200:
        ultima_atualizacao = datetime.now().strftime("%d/%m/%Y %H:%M")
        return resposta.json()

    return None


def obter_ultima_atualizacao():
    return ultima_atualizacao