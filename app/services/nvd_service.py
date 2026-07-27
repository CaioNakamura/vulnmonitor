import requests

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def consultar_vulnerabilidades(fabricante, produto, versao):

    keyword = f"{fabricante} {produto} {versao}"

    resposta = requests.get(
        BASE_URL,
        params={
            "keywordSearch": keyword,
            "resultsPerPage": 20
        },
        timeout=30
    )

    if resposta.status_code != 200:
        return []

    dados = resposta.json()

    vulnerabilidades = []

    for item in dados.get("vulnerabilities", []):

        cve = item["cve"]

        descricao = ""

        for d in cve["descriptions"]:
            if d["lang"] == "en":
                descricao = d["value"]
                break

        cvss = "-"
        severidade = "-"

        metricas = cve.get("metrics", {})

        if "cvssMetricV31" in metricas:

            cvss = metricas["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severidade = metricas["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

        elif "cvssMetricV30" in metricas:

            cvss = metricas["cvssMetricV30"][0]["cvssData"]["baseScore"]
            severidade = metricas["cvssMetricV30"][0]["cvssData"]["baseSeverity"]

        elif "cvssMetricV2" in metricas:

            cvss = metricas["cvssMetricV2"][0]["cvssData"]["baseScore"]
            severidade = metricas["cvssMetricV2"][0]["baseSeverity"]

        vulnerabilidades.append({

            "id": cve["id"],

            "descricao": descricao,

            "cvss": cvss,

            "severidade": severidade,

            "publicado": cve["published"][:10],

            "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"

        })

    return vulnerabilidades