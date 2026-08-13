from sqlalchemy.orm import Session
from app.models.empresa import Empresa


def listar_empresas(db: Session):
    return db.query(Empresa).all()