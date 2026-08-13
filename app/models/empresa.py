from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database import Base


class Empresa(Base):
    __tablename__ = "empresas"

    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True)
    criado_em = Column(DateTime, default=datetime.utcnow)

    ativos = relationship(
        "Ativo",
        back_populates="empresa",
        cascade="all, delete-orphan"
    )