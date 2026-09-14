from app.database import SessionLocal
from app.models import Ativo


db = SessionLocal()

try:

    ativo = (
        db.query(
            Ativo
        )
        .filter(
            Ativo.id == 2
        )
        .first()
    )

    if not ativo:

        print(
            "Ativo ID 2 não encontrado."
        )

    else:

        ativo.email_responsavel = (
            "n8nprojeto.2026@gmail.com"
        )

        db.commit()

        db.refresh(
            ativo
        )

        print()
        print(
            "========================================"
        )

        print(
            "E-MAIL DO ATIVO CONFIGURADO"
        )

        print(
            "========================================"
        )

        print(
            "Ativo:",
            ativo.nome
        )

        print(
            "E-mail:",
            ativo.email_responsavel
        )

        print(
            "========================================"
        )

finally:

    db.close()