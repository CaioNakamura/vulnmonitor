from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import Base


class Vulnerabilidade(Base):
    __tablename__ = "vulnerabilidades"

    id = Column(Integer, primary_key=True, index=True)
    ativo_id = Column(Integer, ForeignKey("ativos.id"), nullable=False)

    cve = Column(String, nullable=False, index=True)
    descricao = Column(String)
    severidade = Column(String)
    cvss = Column(Float)
    publicado = Column(String)
    url = Column(String)

    criado_em = Column(DateTime(timezone=True), server_default=func.now())