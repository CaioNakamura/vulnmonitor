from sqlalchemy import Column, Integer, String

from app.database import Base


class Ativo(Base):
    __tablename__ = "ativos"

    id = Column(Integer, primary_key=True)
    nome = Column(String)
    produto = Column(String)
    versao = Column(String)