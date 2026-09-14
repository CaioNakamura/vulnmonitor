import json
import re

from app.database import SessionLocal

from app.models import (
    Ativo,
    Vulnerabilidade,
    AtivoVulnerabilidade
)


# =========================================================
# UTILITÁRIOS
# =========================================================

def normalizar_token(valor):

    return (
        str(valor or "")
        .strip()
        .lower()
        .replace("_", "")
        .replace("-", "")
        .replace(".", "")
        .replace(" ", "")
    )


def extrair_componentes_cpe(cpe):

    if not cpe:
        return None

    partes = cpe.split(":")

    if len(partes) < 6:
        return None

    if partes[0] != "cpe":
        return None

    if partes[1] != "2.3":
        return None

    return {
        "part": partes[2],
        "vendor": partes[3],
        "product": partes[4],
        "version": partes[5],
        "update": partes[6] if len(partes) > 6 else "*",
        "edition": partes[10] if len(partes) > 10 else "*",
        "language": partes[11] if len(partes) > 11 else "*",
    }


# =========================================================
# CONVERTER VERSÃO PARA NÚMEROS
# =========================================================

def tokenizar_versao(valor):

    texto = str(valor or "").strip().lower()

    if not texto:
        return []

    partes = re.findall(
        r"\d+|[a-z]+",
        texto
    )

    resultado = []

    for parte in partes:

        if parte.isdigit():

            resultado.append(
                (
                    0,
                    int(parte)
                )
            )

        else:

            resultado.append(
                (
                    1,
                    parte
                )
            )

    return resultado


def comparar_versoes(
    esquerda,
    direita
):

    a = tokenizar_versao(
        esquerda
    )

    b = tokenizar_versao(
        direita
    )

    tamanho = max(
        len(a),
        len(b)
    )

    while len(a) < tamanho:
        a.append((0, 0))

    while len(b) < tamanho:
        b.append((0, 0))

    if a < b:
        return -1

    if a > b:
        return 1

    return 0


# =========================================================
# NORMALIZAR BUILD
# =========================================================

def normalizar_build(
    build
):

    texto = str(
        build or ""
    ).strip()

    if not texto:
        return ""

    # Remove "10.0." caso venha da NVD.
    if texto.startswith(
        "10.0."
    ):

        texto = texto[5:]

    # Remove qualquer coisa após espaço.
    texto = texto.split(
        " "
    )[0]

    return texto


# =========================================================
# COMPARAR BUILD
# =========================================================

def comparar_builds(
    build_ativo,
    build_nvd
):
    """
    Compara:

        26200.9445

    com:

        10.0.26200.6899

    """

    ativo = normalizar_build(
        build_ativo
    )

    nvd = normalizar_build(
        build_nvd
    )

    return comparar_versoes(
        ativo,
        nvd
    )


# =========================================================
# BUILD COMPATÍVEL COM CPE MATCH
# =========================================================

def build_compativel(
    ativo,
    match
):
    """
    Determina se a build do ativo está dentro
    dos limites definidos pela NVD.
    """

    build_ativo = getattr(
        ativo,
        "build",
        None
    )

    # -----------------------------------------------------
    # Sem build cadastrada
    # -----------------------------------------------------

    if not build_ativo:

        return True

    inicio_incluindo = match.get(
        "versionStartIncluding"
    )

    inicio_excluindo = match.get(
        "versionStartExcluding"
    )

    fim_incluindo = match.get(
        "versionEndIncluding"
    )

    fim_excluindo = match.get(
        "versionEndExcluding"
    )

    # -----------------------------------------------------
    # Início incluindo
    # -----------------------------------------------------

    if inicio_incluindo:

        if comparar_builds(
            build_ativo,
            inicio_incluindo
        ) < 0:

            return False

    # -----------------------------------------------------
    # Início excluindo
    # -----------------------------------------------------

    if inicio_excluindo:

        if comparar_builds(
            build_ativo,
            inicio_excluindo
        ) <= 0:

            return False

    # -----------------------------------------------------
    # Fim incluindo
    # -----------------------------------------------------

    if fim_incluindo:

        if comparar_builds(
            build_ativo,
            fim_incluindo
        ) > 0:

            return False

    # -----------------------------------------------------
    # Fim excluindo
    # -----------------------------------------------------

    if fim_excluindo:

        if comparar_builds(
            build_ativo,
            fim_excluindo
        ) >= 0:

            return False

    return True


# =========================================================
# CPE COMPATÍVEL
# =========================================================

def cpe_compativel(
    ativo,
    match
):
    """
    Compara o CPE do ativo com um CPE Match da NVD.
    """

    cpe_ativo = getattr(
        ativo,
        "cpe",
        None
    )

    if not cpe_ativo:
        return False

    criterio = match.get(
        "criteria",
        ""
    )

    partes_ativo = (
        extrair_componentes_cpe(
            cpe_ativo
        )
    )

    partes_nvd = (
        extrair_componentes_cpe(
            criterio
        )
    )

    if (
        not partes_ativo
        or
        not partes_nvd
    ):

        return False

    # =====================================================
    # PART
    # =====================================================

    if (
        partes_nvd["part"] != "*"
        and
        partes_ativo["part"]
        !=
        partes_nvd["part"]
    ):

        return False

    # =====================================================
    # VENDOR
    # =====================================================

    if (
        partes_nvd["vendor"] != "*"
        and
        normalizar_token(
            partes_ativo["vendor"]
        )
        !=
        normalizar_token(
            partes_nvd["vendor"]
        )
    ):

        return False

    # =====================================================
    # PRODUTO
    # =====================================================

    produto_ativo = normalizar_token(
        partes_ativo["product"]
    )

    produto_nvd = normalizar_token(
        partes_nvd["product"]
    )

    if produto_nvd != "*":

        # Para Windows 11 25H2:
        #
        # windows_11_25h2
        #
        # precisa corresponder ao ativo.

        if (
            produto_ativo
            !=
            produto_nvd
        ):

            return False

    # =====================================================
    # VERSÃO DO CPE
    # =====================================================

    versao_nvd = partes_nvd[
        "version"
    ]

    versao_ativo = partes_ativo[
        "version"
    ]

    # -----------------------------------------------------
    # CPE com versão ANY
    # -----------------------------------------------------

    if versao_nvd not in (
        "*",
        "-"
    ):

        if normalizar_token(
            versao_ativo
        ) != normalizar_token(
            versao_nvd
        ):

            return False

    # -----------------------------------------------------
    # BUILD
    # -----------------------------------------------------

    if not build_compativel(
        ativo,
        match
    ):

        return False

    return True


# =========================================================
# VERIFICAR VULNERABILIDADE
# =========================================================

def vulnerabilidade_afeta_ativo(
    ativo,
    vulnerabilidade
):
    """
    Verifica se uma vulnerabilidade afeta
    o ativo por meio dos CPEs armazenados.
    """

    cpes = vulnerabilidade.get(
        "cpes",
        []
    )

    if not cpes:
        return False

    for match in cpes:

        if isinstance(
            match,
            str
        ):

            match = {
                "criteria": match,
                "vulnerable": True
            }

        if match.get(
            "vulnerable"
        ) is False:

            continue

        if cpe_compativel(
            ativo,
            match
        ):

            return True

    return False


# =========================================================
# CONVERTER VULNERABILIDADE
# =========================================================

def vulnerabilidade_para_dict(
    vulnerabilidade
):

    try:

        cpes = json.loads(
            vulnerabilidade.cpes
            or "[]"
        )

    except Exception:

        cpes = []

    try:

        affected = json.loads(
            vulnerabilidade.affected
            or "[]"
        )

    except Exception:

        affected = []

    return {
        "id": vulnerabilidade.cve,
        "descricao": vulnerabilidade.descricao,
        "severidade": vulnerabilidade.severidade,
        "cvss": vulnerabilidade.cvss,
        "publicado": vulnerabilidade.publicado,
        "url": vulnerabilidade.url,
        "cpes": cpes,
        "affected": affected
    }


# =========================================================
# MAIN
# =========================================================

def main():

    db = SessionLocal()

    try:

        print()
        print(
            "========================================"
        )

        print(
            "REPROCESSAMENTO PRECISO POR CPE/BUILD"
        )

        print(
            "========================================"
        )

        ativos = (
            db.query(
                Ativo
            )
            .all()
        )

        vulnerabilidades = (
            db.query(
                Vulnerabilidade
            )
            .all()
        )

        print(
            "Ativos:",
            len(ativos)
        )

        print(
            "Vulnerabilidades:",
            len(vulnerabilidades)
        )

        total_criados = 0

        for ativo in ativos:

            print()
            print(
                "----------------------------------------"
            )

            print(
                "ATIVO:",
                ativo.nome
            )

            print(
                "PRODUTO:",
                ativo.produto
            )

            print(
                "VERSÃO:",
                ativo.versao
            )

            print(
                "BUILD:",
                getattr(
                    ativo,
                    "build",
                    None
                )
            )

            print(
                "CPE:",
                ativo.cpe
            )

            print(
                "----------------------------------------"
            )

            criados_ativo = 0

            for vulnerabilidade in vulnerabilidades:

                # -----------------------------------------
                # Já relacionado?
                # -----------------------------------------

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

                    continue

                dados = (
                    vulnerabilidade_para_dict(
                        vulnerabilidade
                    )
                )

                if not vulnerabilidade_afeta_ativo(
                    ativo,
                    dados
                ):

                    continue

                db.add(
                    AtivoVulnerabilidade(

                        ativo_id=
                            ativo.id,

                        vulnerabilidade_id=
                            vulnerabilidade.id,

                        notificado=0
                    )
                )

                criados_ativo += 1

                total_criados += 1

                print(
                    "RELACIONAMENTO:",
                    ativo.nome,
                    "->",
                    vulnerabilidade.cve
                )

            print()
            print(
                "Relacionamentos criados para este ativo:",
                criados_ativo
            )

            db.commit()

        print()
        print(
            "========================================"
        )

        print(
            "REPROCESSAMENTO CONCLUÍDO"
        )

        print(
            "========================================"
        )

        print(
            "Total de relacionamentos criados:",
            total_criados
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
            "ERRO NO REPROCESSAMENTO"
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