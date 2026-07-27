from app.services.nvd_service import consultar_vulnerabilidades


def buscar_vulnerabilidades(ativo):

    resposta = consultar_vulnerabilidades(
        ativo.fabricante,
        ativo.produto,
        ativo.versao
    )

    if not resposta:
        return []

    lista = []

    for item in resposta.get("vulnerabilities", []):

        cve = item.get("cve", {})

        descricao = ""

        for d in cve.get("descriptions", []):

            if d["lang"] == "en":
                descricao = d["value"]
                break

        cvss = "-"
        severidade = "-"

        metricas = cve.get("metrics", {})

        if "cvssMetricV31" in metricas:

            dados = metricas["cvssMetricV31"][0]["cvssData"]

            cvss = dados["baseScore"]
            severidade = dados["baseSeverity"]

        elif "cvssMetricV30" in metricas:

            dados = metricas["cvssMetricV30"][0]["cvssData"]

            cvss = dados["baseScore"]
            severidade = dados["baseSeverity"]

        elif "cvssMetricV2" in metricas:

            dados = metricas["cvssMetricV2"][0]["cvssData"]

            cvss = dados["baseScore"]
            severidade = metricas["cvssMetricV2"][0]["baseSeverity"]

        lista.append({

            "id": cve["id"],

            "descricao": descricao,

            "cvss": cvss,

            "severidade": severidade,

            "publicado": cve["published"][:10],

            "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"

        })

    return lista