from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

from app.database import Base


class Atualizacao(Base):
    __tablename__ = "atualizacoes"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    iniciada_em = Column(
        DateTime,
        nullable=False
    )

    finalizada_em = Column(
        DateTime,
        nullable=True
    )

    status = Column(
        String,
        nullable=False,
        default="EM_ANDAMENTO"
    )

    quantidade_cves = Column(
        Integer,
        default=0
    )

    erro = Column(
        String,
        nullable=True
    )

    criado_em = Column(
        DateTime,
        server_default=func.now()
    )