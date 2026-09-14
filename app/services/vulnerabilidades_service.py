from datetime import datetime

from sqlalchemy.orm import Session

from app.models import (
    AtivoVulnerabilidade,
    Vulnerabilidade
)


# =========================================================
# BUSCAR VULNERABILIDADES DO ATIVO
# =========================================================

def buscar_vulnerabilidades(
    db: Session,
    ativo_id: int
):

    registros = (
        db.query(
            Vulnerabilidade
        )
        .join(
            AtivoVulnerabilidade,
            AtivoVulnerabilidade.vulnerabilidade_id
            == Vulnerabilidade.id
        )
        .filter(
            AtivoVulnerabilidade.ativo_id
            == ativo_id
        )
        .all()
    )

    vulnerabilidades = []

    for vulnerabilidade in registros:

        vulnerabilidades.append({

            "id":
                vulnerabilidade.id,

            "cve":
                vulnerabilidade.cve,

            "descricao":
                vulnerabilidade.descricao,

            "severidade":
                vulnerabilidade.severidade,

            "cvss":
                vulnerabilidade.cvss,

            "publicado":
                vulnerabilidade.publicado,

            "url":
                vulnerabilidade.url
        })

    # -----------------------------------------------------
    # ORDENA POR PUBLICAÇÃO
    # -----------------------------------------------------

    def converter_data(item):

        try:

            return datetime.strptime(
                item.get(
                    "publicado"
                ),
                "%d/%m/%Y"
            )

        except (
            ValueError,
            TypeError
        ):

            return datetime.min

    vulnerabilidades.sort(
        key=converter_data,
        reverse=True
    )

    return vulnerabilidades


# =========================================================
# LISTAR ORM
# =========================================================

def listar_vulnerabilidades_ativo(
    db: Session,
    ativo_id: int
):

    resultados = (
        db.query(
            Vulnerabilidade
        )
        .join(
            AtivoVulnerabilidade,
            AtivoVulnerabilidade.vulnerabilidade_id
            == Vulnerabilidade.id
        )
        .filter(
            AtivoVulnerabilidade.ativo_id
            == ativo_id
        )
        .all()
    )

    # Ordenação correta por data
    resultados.sort(
        key=lambda item: (
            datetime.strptime(
                item.publicado,
                "%d/%m/%Y"
            )
            if item.publicado
            else datetime.min
        ),
        reverse=True
    )

    return resultados


# =========================================================
# CONTAR
# =========================================================

def contar_vulnerabilidades(
    db: Session,
    ativo_id: int
):

    return (
        db.query(
            AtivoVulnerabilidade
        )
        .filter(
            AtivoVulnerabilidade.ativo_id
            == ativo_id
        )
        .count()
    )


# =========================================================
# RESUMO
# =========================================================

def resumir_vulnerabilidades(
    vulnerabilidades
):

    resumo = {

        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    for item in vulnerabilidades:

        if isinstance(
            item,
            dict
        ):

            severidade = item.get(
                "severidade",
                "UNKNOWN"
            )

        else:

            severidade = getattr(
                item,
                "severidade",
                "UNKNOWN"
            )

        severidade = (
            severidade
            or "UNKNOWN"
        ).upper()

        if severidade in resumo:

            resumo[severidade] += 1

        else:

            resumo["UNKNOWN"] += 1

    return resumo