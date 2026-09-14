from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class Vulnerabilidade(Base):
    __tablename__ = "vulnerabilidades"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    cve = Column(
        String,
        nullable=False,
        unique=True,
        index=True
    )

    descricao = Column(
        Text,
        nullable=True
    )

    severidade = Column(
        String,
        nullable=True
    )

    cvss = Column(
        Float,
        nullable=True
    )

    publicado = Column(
        String,
        nullable=True
    )

    url = Column(
        String,
        nullable=True
    )

    # =====================================================
    # CPEs
    # =====================================================

    cpes = Column(
        Text,
        nullable=True
    )

    # =====================================================
    # PRODUTOS AFETADOS
    # =====================================================
    #
    # Armazenado como JSON.
    #
    # Exemplo:
    #
    # [
    #   {
    #       "source": "...",
    #       "vendor": "Rara Themes",
    #       "product": "Rara One Click Demo Import",
    #       "defaultStatus": "unaffected",
    #       "versions": [...]
    #   }
    # ]
    #
    # =====================================================

    affected = Column(
        Text,
        nullable=True
    )

    criado_em = Column(
        DateTime,
        server_default=func.now()
    )

    # =====================================================
    # RELACIONAMENTO
    # =====================================================

    ativos_relacionados = relationship(
        "AtivoVulnerabilidade",
        back_populates="vulnerabilidade",
        cascade="all, delete-orphan"
    )