from sqlalchemy import Column, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class AtivoVulnerabilidade(Base):
    __tablename__ = "ativo_vulnerabilidades"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    ativo_id = Column(
        Integer,
        ForeignKey("ativos.id"),
        nullable=False
    )

    vulnerabilidade_id = Column(
        Integer,
        ForeignKey("vulnerabilidades.id"),
        nullable=False
    )

    detectada_em = Column(
        DateTime,
        server_default=func.now()
    )

    notificado = Column(
        Integer,
        default=0
    )

    ativo = relationship(
        "Ativo",
        back_populates="vulnerabilidades_relacionadas"
    )

    vulnerabilidade = relationship(
        "Vulnerabilidade",
        back_populates="ativos_relacionados"
    )