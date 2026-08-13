from sqlalchemy.orm import Session
from app.models import Ativo


EMPRESA_PADRAO_ID = 1


def listar_ativos(db: Session):
    ativos = db.query(Ativo).all()
    print("ATIVOS LIDOS:", ativos)
    return ativos


def cadastrar_ativo(
    db: Session,
    nome: str,
    produto: str,
    versao: str
):
    ativo = Ativo(
        empresa_id=EMPRESA_PADRAO_ID,
        nome=nome,
        produto=produto,
        versao=versao
    )

    db.add(ativo)
    db.commit()
    db.refresh(ativo)

    return ativo


def buscar_ativo(db: Session, id: int):
    return db.query(Ativo).filter(Ativo.id == id).first()


def editar_ativo(
    db: Session,
    id: int,
    nome: str,
    produto: str,
    versao: str
):
    ativo = buscar_ativo(db, id)

    if ativo:
        ativo.nome = nome
        ativo.produto = produto
        ativo.versao = versao

        db.commit()
        db.refresh(ativo)

    return ativo


def excluir_ativo(db: Session, id: int):
    ativo = buscar_ativo(db, id)

    if ativo:
        db.delete(ativo)
        db.commit()


def contar_ativos(db: Session):
    return db.query(Ativo).count()