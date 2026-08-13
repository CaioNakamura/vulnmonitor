from sqlalchemy.orm import Session
from app.models import Vulnerabilidade
from app.services.nvd_service import consultar_vulnerabilidades


def buscar_vulnerabilidades(ativo):
    """
    Consulta vulnerabilidades na NVD para um ativo.
    """
    return consultar_vulnerabilidades(
        ativo.produto,
        ativo.versao
    )


def salvar_vulnerabilidades(
    db: Session,
    ativo_id: int,
    vulnerabilidades: list
):
    """
    Salva vulnerabilidades no banco evitando duplicados.
    """

    salvas = 0

    for item in vulnerabilidades:

        existente = (
            db.query(Vulnerabilidade)
            .filter(
                Vulnerabilidade.ativo_id == ativo_id,
                Vulnerabilidade.cve == item["id"]
            )
            .first()
        )

        if existente:
            continue

        nova = Vulnerabilidade(
            ativo_id=ativo_id,
            cve=item["id"],
            descricao=item["descricao"],
            severidade=item["severidade"],
            cvss=item["cvss"],
            publicado=item["publicado"],
            url=item["url"]
        )

        db.add(nova)
        salvas += 1

    db.commit()

    return salvas