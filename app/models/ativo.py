from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime
)

from sqlalchemy.orm import relationship

from datetime import datetime

from app.database import Base


class Ativo(Base):

    __tablename__ = "ativos"

    # =====================================================
    # ID
    # =====================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    # =====================================================
    # EMPRESA
    # =====================================================

    empresa_id = Column(
        Integer,
        ForeignKey(
            "empresas.id"
        ),
        nullable=False
    )

    # =====================================================
    # NOME
    # =====================================================

    nome = Column(
        String,
        nullable=False
    )

    # =====================================================
    # PRODUTO
    # =====================================================

    produto = Column(
        String,
        nullable=False
    )

    # =====================================================
    # VERSÃO
    # =====================================================

    versao = Column(
        String,
        nullable=False
    )

    # =====================================================
    # BUILD
    # =====================================================

    build = Column(
        String,
        nullable=True
    )

    # =====================================================
    # CPE
    # =====================================================

    cpe = Column(
        String,
        nullable=True
    )

    # =====================================================
    # E-MAIL DO RESPONSÁVEL
    # =====================================================

    email_responsavel = Column(
        String,
        nullable=True
    )

    # =====================================================
    # DATA DE CRIAÇÃO
    # =====================================================

    criado_em = Column(
        DateTime,
        default=datetime.utcnow
    )

    # =====================================================
    # RELACIONAMENTO COM EMPRESA
    # =====================================================

    empresa = relationship(
        "Empresa",
        back_populates="ativos"
    )

    # =====================================================
    # RELACIONAMENTO COM VULNERABILIDADES
    # =====================================================

    vulnerabilidades_relacionadas = relationship(
        "AtivoVulnerabilidade",
        back_populates="ativo",
        cascade="all, delete-orphan"
    )