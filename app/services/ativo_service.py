from sqlalchemy.orm import Session

from app.models import Ativo


def listar_ativos(db: Session):
    return db.query(Ativo).order_by(Ativo.id).all()


def cadastrar_ativo(
    db: Session,
    nome: str,
    produto: str,
    versao: str,
    email_responsavel: str = ""
):
    ativo = Ativo(
        nome=nome,
        produto=produto,
        versao=versao,
        email_responsavel=email_responsavel.strip() or None
    )

    db.add(ativo)
    db.commit()
    db.refresh(ativo)

    return ativo


def editar_ativo(
    db: Session,
    id: int,
    nome: str,
    produto: str,
    versao: str,
    email_responsavel: str = ""
):
    ativo = db.query(Ativo).filter(
        Ativo.id == id
    ).first()

    if not ativo:
        return None

    ativo.nome = nome
    ativo.produto = produto
    ativo.versao = versao
    ativo.email_responsavel = (
        email_responsavel.strip()
        or None
    )

    db.commit()
    db.refresh(ativo)

    return ativo


def excluir_ativo(
    db: Session,
    id: int
):
    ativo = db.query(Ativo).filter(
        Ativo.id == id
    ).first()

    if not ativo:
        return None

    db.delete(ativo)
    db.commit()

    return True