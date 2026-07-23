from sqlalchemy.orm import Session
from app.models import Ativo

def listar_ativos(db: Session):
    return db.query(Ativo).all()

def cadastrar_ativo(
    db: Session,
    nome: str,
    fabricante: str,
    produto: str,
    versao: str
):
    ativo = Ativo(
        nome=nome,
        fabricante=fabricante,
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
    fabricante: str,
    produto: str,
    versao: str
):
    ativo = buscar_ativo(db, id)

    if ativo:

        ativo.nome = nome
        ativo.fabricante = fabricante
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