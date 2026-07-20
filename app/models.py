from sqlalchemy import Column, Integer, String

from app.database import Base


class Ativo(Base):
    __tablename__ = "ativos"

    id = Column(Integer, primary_key=True, index=True)

    nome = Column(String, nullable=False)

    fabricante = Column(String)

    produto = Column(String)

    versao = Column(String)