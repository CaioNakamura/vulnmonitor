import json
import time
import requests

from app.database import SessionLocal
from app.models import (
    Ativo,
    Vulnerabilidade,
    AtivoVulnerabilidade
)


NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

RESULTADOS_POR_PAGINA = 200
INTERVALO = 6
MAX_TENTATIVAS = 3


def consultar_nvd_por_cpe(cpe):

    resultados = []

    start_index = 0

    while True:

        parametros = {
            "cpeName": cpe,
            "resultsPerPage": RESULTADOS_POR_PAGINA,
            "startIndex": start_index
        }

        dados = None

        for tentativa in range(
            1,
            MAX_TENTATIVAS + 1
        ):

            try:

                print()
                print("Consultando NVD por CPE")
                print("CPE:", cpe)
                print("StartIndex:", start_index)

                resposta = requests.get(
                    NVD_API_URL,
                    params=parametros,
                    timeout=60
                )

                if resposta.status_code == 429:

                    espera = (
                        15 * tentativa
                    )

                    print(
                        "HTTP 429."
                    )

                    print(
                        f"Aguardando {espera}s..."
                    )

                    time.sleep(
                        espera
                    )

                    continue

                resposta.raise_for_status()

                dados = resposta.json()

                break

            except requests.exceptions.RequestException as erro:

                if tentativa >= MAX_TENTATIVAS:

                    raise

                espera = (
                    10 * tentativa
                )

                print(
                    "Erro:",
                    erro
                )

                print(
                    f"Tentando novamente "
                    f"em {espera}s..."
                )

                time.sleep(
                    espera
                )

        if dados is None:

            break

        total = dados.get(
            "totalResults",
            0
        )

        candidatos = dados.get(
            "vulnerabilities",
            []
        )

        print(
            "Total encontrado:",
            total
        )

        print(
            "Recebidos:",
            len(candidatos)
        )

        resultados.extend(
            candidatos
        )

        if not candidatos:

            break

        start_index += len(
            candidatos
        )

        if start_index >= total:

            break

        time.sleep(
            INTERVALO
        )

    return resultados


def main():

    db = SessionLocal()

    try:

        ativo = (
            db.query(
                Ativo
            )
            .filter(
                Ativo.id == 2
            )
            .first()
        )

        if not ativo:

            print(
                "Ativo ID 2 não encontrado."
            )

            return

        if not ativo.cpe:

            print(
                "O ativo não possui CPE."
            )

            return

        print()
        print(
            "========================================"
        )

        print(
            "CONSULTA WINDOWS 11 25H2"
        )

        print(
            "========================================"
        )

        print(
            "Ativo:",
            ativo.nome
        )

        print(
            "CPE:",
            ativo.cpe
        )

        resultados = consultar_nvd_por_cpe(
            ativo.cpe
        )

        print()
        print(
            "CVEs encontradas:",
            len(resultados)
        )

        novas = 0
        relacionamentos = 0

        for item in resultados:

            cve = item.get(
                "cve",
                {}
            )

            cve_id = cve.get(
                "id"
            )

            if not cve_id:

                continue

            existente = (
                db.query(
                    Vulnerabilidade
                )
                .filter(
                    Vulnerabilidade.cve
                    == cve_id
                )
                .first()
            )

            if not existente:

                descricao = ""

                for d in cve.get(
                    "descriptions",
                    []
                ):

                    if d.get(
                        "lang"
                    ) == "en":

                        descricao = d.get(
                            "value",
                            ""
                        )

                        break

                metrics = cve.get(
                    "metrics",
                    {}
                )

                cvss = 0.0
                severidade = "UNKNOWN"

                for nome in (
                    "cvssMetricV40",
                    "cvssMetricV31",
                    "cvssMetricV30",
                    "cvssMetricV2"
                ):

                    if metrics.get(nome):

                        metric = metrics[nome][0]

                        dados_cvss = metric.get(
                            "cvssData",
                            {}
                        )

                        cvss = dados_cvss.get(
                            "baseScore",
                            0.0
                        )

                        severidade = dados_cvss.get(
                            "baseSeverity",
                            "UNKNOWN"
                        )

                        break

                publicado = (
                    cve.get(
                        "published",
                        ""
                    )[:10]
                )

                if publicado:

                    partes = publicado.split(
                        "-"
                    )

                    if len(partes) == 3:

                        publicado = (
                            f"{partes[2]}/"
                            f"{partes[1]}/"
                            f"{partes[0]}"
                        )

                existente = Vulnerabilidade(

                    cve=cve_id,

                    descricao=descricao,

                    severidade=severidade,

                    cvss=cvss,

                    publicado=publicado,

                    url=(
                        "https://nvd.nist.gov/vuln/detail/"
                        + cve_id
                    ),

                    cpes=json.dumps(
                        cve.get(
                            "configurations",
                            []
                        ),
                        ensure_ascii=False
                    )
                )

                db.add(
                    existente
                )

                db.flush()

                novas += 1

            # ---------------------------------------------
            # RELACIONAMENTO
            # ---------------------------------------------

            relacao = (
                db.query(
                    AtivoVulnerabilidade
                )
                .filter(
                    AtivoVulnerabilidade.ativo_id
                    == ativo.id,

                    AtivoVulnerabilidade.vulnerabilidade_id
                    == existente.id
                )
                .first()
            )

            if not relacao:

                db.add(
                    AtivoVulnerabilidade(

                        ativo_id=ativo.id,

                        vulnerabilidade_id=existente.id,

                        notificado=0
                    )
                )

                relacionamentos += 1

                print(
                    "RELACIONAMENTO:",
                    ativo.nome,
                    "->",
                    cve_id
                )

        db.commit()

        print()
        print(
            "========================================"
        )

        print(
            "CONCLUÍDO"
        )

        print(
            "========================================"
        )

        print(
            "CVEs encontradas:",
            len(resultados)
        )

        print(
            "CVEs novas:",
            novas
        )

        print(
            "Relacionamentos:",
            relacionamentos
        )

        print(
            "========================================"
        )

    except Exception as erro:

        db.rollback()

        print()
        print(
            "========================================"
        )

        print(
            "ERRO"
        )

        print(
            "========================================"
        )

        print(
            erro
        )

        raise

    finally:

        db.close()


if __name__ == "__main__":

    main()