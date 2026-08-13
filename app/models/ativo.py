from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database import Base


class Ativo(Base):
    __tablename__ = "ativos"

    id = Column(Integer, primary_key=True, index=True)

    empresa_id = Column(
        Integer,
        ForeignKey("empresas.id"),
        nullable=False
    )

    nome = Column(String, nullable=False)
    produto = Column(String, nullable=False)
    versao = Column(String, nullable=False)

    criado_em = Column(DateTime, default=datetime.utcnow)

    empresa = relationship(
        "Empresa",
        back_populates="ativos"
    )