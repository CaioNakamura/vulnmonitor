import json
import time
import requests

from app.database import SessionLocal

from app.models import (
    Ativo,
    Vulnerabilidade,
    AtivoVulnerabilidade
)

from app.services.atualizacao_service import (
    extrair_cpe_matches,
    extrair_affected,
    extrair_descricao,
    extrair_cvss,
    ativo_e_afetado,
    vulnerabilidade_para_dict,
)


NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

RESULTADOS_POR_PAGINA = 200

INTERVALO_ENTRE_PAGINAS = 6

MAX_TENTATIVAS = 3


# =========================================================
# CONSULTAR NVD POR CPE
# =========================================================

def consultar_nvd_por_cpe(
    cpe
):

    resultados = []

    start_index = 0

    while True:

        parametros = {

            "cpeName":
                cpe,

            "resultsPerPage":
                RESULTADOS_POR_PAGINA,

            "startIndex":
                start_index
        }

        dados = None

        # -------------------------------------------------
        # TENTATIVAS
        # -------------------------------------------------

        for tentativa in range(
            1,
            MAX_TENTATIVAS + 1
        ):

            try:

                print()
                print(
                    "Consultando NVD por CPE..."
                )

                print(
                    "CPE:",
                    cpe
                )

                print(
                    "StartIndex:",
                    start_index
                )

                resposta = requests.get(
                    NVD_API_URL,
                    params=parametros,
                    timeout=60
                )

                # -----------------------------------------
                # HTTP 429
                # -----------------------------------------

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
                    f"Nova tentativa em "
                    f"{espera}s..."
                )

                time.sleep(
                    espera
                )

        if dados is None:

            raise RuntimeError(
                "NVD não retornou dados."
            )

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

        print(
            f"Aguardando "
            f"{INTERVALO_ENTRE_PAGINAS}s..."
        )

        time.sleep(
            INTERVALO_ENTRE_PAGINAS
        )

    return resultados


# =========================================================
# SALVAR VULNERABILIDADE
# =========================================================

def salvar_vulnerabilidade(
    db,
    cve
):
    """
    Cria ou atualiza uma CVE no banco.
    """

    cve_id = cve.get(
        "id"
    )

    if not cve_id:

        return None, False

    existente = (
        db.query(
            Vulnerabilidade
        )
        .filter(
            Vulnerabilidade.cve
            ==
            cve_id
        )
        .first()
    )

    descricao = extrair_descricao(
        cve
    )

    cvss, severidade = extrair_cvss(
        cve
    )

    publicado = cve.get(
        "published",
        ""
    )[:10]

    if publicado:

        try:

            partes = publicado.split(
                "-"
            )

            if len(partes) == 3:

                publicado = (
                    f"{partes[2]}/"
                    f"{partes[1]}/"
                    f"{partes[0]}"
                )

        except Exception:

            pass

    url = (
        "https://nvd.nist.gov/vuln/detail/"
        +
        cve_id
    )

    cpes = extrair_cpe_matches(
        cve
    )

    affected = extrair_affected(
        cve
    )

    cpes_json = json.dumps(
        cpes,
        ensure_ascii=False
    )

    affected_json = json.dumps(
        affected,
        ensure_ascii=False
    )

    # -----------------------------------------------------
    # EXISTENTE
    # -----------------------------------------------------

    if existente:

        existente.descricao = (
            descricao
        )

        existente.cvss = (
            cvss
        )

        existente.severidade = (
            severidade
        )

        existente.publicado = (
            publicado
        )

        existente.url = (
            url
        )

        existente.cpes = (
            cpes_json
        )

        existente.affected = (
            affected_json
        )

        db.flush()

        return existente, False

    # -----------------------------------------------------
    # NOVA
    # -----------------------------------------------------

    nova = Vulnerabilidade(

        cve=cve_id,

        descricao=descricao,

        severidade=severidade,

        cvss=cvss,

        publicado=publicado,

        url=url,

        cpes=cpes_json,

        affected=affected_json
    )

    db.add(
        nova
    )

    db.flush()

    return nova, True


# =========================================================
# RELACIONAR
# =========================================================

def criar_relacionamento(
    db,
    ativo,
    vulnerabilidade
):

    existente = (
        db.query(
            AtivoVulnerabilidade
        )
        .filter(
            AtivoVulnerabilidade.ativo_id
            ==
            ativo.id,

            AtivoVulnerabilidade.vulnerabilidade_id
            ==
            vulnerabilidade.id
        )
        .first()
    )

    if existente:

        return False

    db.add(
        AtivoVulnerabilidade(

            ativo_id=
                ativo.id,

            vulnerabilidade_id=
                vulnerabilidade.id,

            notificado=0
        )
    )

    return True


# =========================================================
# MAIN
# =========================================================

def main():

    db = SessionLocal()

    try:

        # -------------------------------------------------
        # BUSCAR WINDOWS 11 25H2
        # -------------------------------------------------

        ativo = (
            db.query(
                Ativo
            )
            .filter(
                Ativo.produto
                .ilike(
                    "%Windows 11%"
                )
            )
            .filter(
                Ativo.versao
                ==
                "25H2"
            )
            .first()
        )

        if not ativo:

            print()
            print(
                "========================================"
            )

            print(
                "ATIVO WINDOWS 11 25H2 NÃO ENCONTRADO"
            )

            print(
                "========================================"
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
            "IMPORTAÇÃO WINDOWS 11 25H2"
        )

        print(
            "========================================"
        )

        print(
            "Ativo:",
            ativo.nome
        )

        print(
            "Produto:",
            ativo.produto
        )

        print(
            "Versão:",
            ativo.versao
        )

        print(
            "CPE:",
            ativo.cpe
        )

        # -------------------------------------------------
        # CONSULTA
        # -------------------------------------------------

        candidatos = (
            consultar_nvd_por_cpe(
                ativo.cpe
            )
        )

        print()
        print(
            "========================================"
        )

        print(
            "PROCESSANDO CANDIDATOS"
        )

        print(
            "========================================"
        )

        total_candidatos = len(
            candidatos
        )

        processadas = 0

        relacionadas = 0

        novas = 0

        ignoradas = 0

        # -------------------------------------------------
        # PROCESSAMENTO
        # -------------------------------------------------

        for item in candidatos:

            cve = item.get(
                "cve",
                {}
            )

            if not cve:

                continue

            cve_id = cve.get(
                "id"
            )

            processadas += 1

            # -------------------------------------------------
            # EXTRAIR CPEs
            # -------------------------------------------------

            cpes = (
                extrair_cpe_matches(
                    cve
                )
            )

            affected = (
                extrair_affected(
                    cve
                )
            )

            dados = {

                "id":
                    cve_id,

                "descricao":
                    extrair_descricao(
                        cve
                    ),

                "cvss":
                    extrair_cvss(
                        cve
                    )[0],

                "severidade":
                    extrair_cvss(
                        cve
                    )[1],

                "publicado":
                    cve.get(
                        "published",
                        ""
                    )[:10],

                "url":
                    (
                        "https://nvd.nist.gov/vuln/detail/"
                        +
                        cve_id
                    ),

                "cpes":
                    cpes,

                "affected":
                    affected
            }

            # -------------------------------------------------
            # CORRELAÇÃO REAL
            # -------------------------------------------------

            if not ativo_e_afetado(
                ativo,
                dados
            ):

                ignoradas += 1

                continue

            # -------------------------------------------------
            # SALVAR
            # -------------------------------------------------

            vulnerabilidade, nova = (
                salvar_vulnerabilidade(
                    db,
                    cve
                )
            )

            if nova:

                novas += 1

            # -------------------------------------------------
            # RELACIONAR
            # -------------------------------------------------

            if criar_relacionamento(
                db,
                ativo,
                vulnerabilidade
            ):

                relacionadas += 1

                print(
                    "RELACIONAMENTO:",
                    ativo.nome,
                    "->",
                    cve_id
                )

            # -------------------------------------------------
            # COMMIT A CADA 20
            # -------------------------------------------------

            if processadas % 20 == 0:

                db.commit()

                print(
                    f"Progresso: "
                    f"{processadas}/"
                    f"{total_candidatos}"
                )

        # -------------------------------------------------
        # COMMIT FINAL
        # -------------------------------------------------

        db.commit()

        print()
        print(
            "========================================"
        )

        print(
            "IMPORTAÇÃO CONCLUÍDA"
        )

        print(
            "========================================"
        )

        print(
            "Candidatos recebidos:",
            total_candidatos
        )

        print(
            "Processados:",
            processadas
        )

        print(
            "CVEs novas:",
            novas
        )

        print(
            "Relacionamentos criados:",
            relacionadas
        )

        print(
            "Ignoradas:",
            ignoradas
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
            "ERRO NA IMPORTAÇÃO"
        )

        print(
            "========================================"
        )

        print(
            erro
        )

        print(
            "========================================"
        )

        raise

    finally:

        db.close()


if __name__ == "__main__":

    main()