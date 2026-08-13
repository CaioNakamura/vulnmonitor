from datetime import datetime
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def normalizar_produto(produto: str) -> str:
    """
    Ajusta nomes comuns para melhorar a busca na NVD.
    """
    p = produto.strip().lower()

    mapa = {
        "kali linux": "kali",
        "kali": "kali",
        "windows 11": "windows",
        "windows 10": "windows",
        "microsoft windows": "windows",
        "ubuntu linux": "ubuntu",
        "debian linux": "debian",
        "red hat enterprise linux": "rhel",
        "apache http server": "apache",
        "nginx web server": "nginx",
        "openssl": "openssl",
    }

    return mapa.get(p, p)


def consultar_vulnerabilidades(produto: str, versao: str):
    produto_busca = normalizar_produto(produto)

    vulnerabilidades = []

    # Primeira tentativa: produto + versão
    termos_busca = []

    if versao and versao.strip():
        termos_busca.append(f"{produto_busca} {versao.strip()}")

    # Segunda tentativa: apenas produto
    termos_busca.append(produto_busca)

    for keyword in termos_busca:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20
        }

        try:
            response = requests.get(NVD_API_URL, params=params, timeout=20)
            response.raise_for_status()

            dados = response.json()
            itens = dados.get("vulnerabilities", [])

            if itens:
                for item in itens:
                    cve = item.get("cve", {})

                    cve_id = cve.get("id", "N/A")

                    # Descrição em inglês
                    descricao = "Sem descrição"
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            descricao = d.get("value", descricao)
                            break

                    publicado = cve.get("published", "")

                    # Formata data para padrão brasileiro
                    if publicado:
                        try:
                            data_formatada = datetime.strptime(
                                publicado[:10],
                                "%Y-%m-%d"
                            ).strftime("%d/%m/%Y")
                        except Exception:
                            data_formatada = publicado[:10]
                    else:
                        data_formatada = ""

                    metrics = cve.get("metrics", {})
                    cvss = 0.0
                    severidade = "UNKNOWN"

                    if "cvssMetricV31" in metrics:
                        metric = metrics["cvssMetricV31"][0]
                        cvss = metric["cvssData"].get("baseScore", 0.0)
                        severidade = metric.get("baseSeverity", "UNKNOWN")

                    elif "cvssMetricV30" in metrics:
                        metric = metrics["cvssMetricV30"][0]
                        cvss = metric["cvssData"].get("baseScore", 0.0)
                        severidade = metric.get("baseSeverity", "UNKNOWN")

                    elif "cvssMetricV2" in metrics:
                        metric = metrics["cvssMetricV2"][0]
                        cvss = metric["cvssData"].get("baseScore", 0.0)
                        severidade = metric.get("baseSeverity", "UNKNOWN")

                    vulnerabilidades.append({
                        "id": cve_id,
                        "descricao": descricao,
                        "cvss": cvss,
                        "severidade": severidade,
                        "publicado": data_formatada,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })

                # Encontrou resultados, não precisa tentar outros termos
                break

        except Exception as e:
            print("Erro ao consultar NVD:", e)

    # Remove duplicados
    vistos = set()
    unicos = []

    for v in vulnerabilidades:
        if v["id"] not in vistos:
            vistos.add(v["id"])
            unicos.append(v)

    # Ordena do mais recente para o mais antigo
    def chave_data(item):
        try:
            return datetime.strptime(item["publicado"], "%d/%m/%Y")
        except Exception:
            return datetime.min

    unicos.sort(key=chave_data, reverse=True)

    return unicos


def resumir_vulnerabilidades(vulnerabilidades):
    resumo = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    for v in vulnerabilidades:
        sev = v.get("severidade", "UNKNOWN")

        if sev in resumo:
            resumo[sev] += 1
        else:
            resumo["UNKNOWN"] += 1

    return resumo


def obter_ultima_atualizacao():
    return datetime.now().strftime("%d/%m/%Y %H:%M")