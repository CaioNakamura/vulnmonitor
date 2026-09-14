from app.database import SessionLocal
from app.models import Ativo
from app.services.ativo_service import gerar_cpe


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

        ativo.produto = (
            "Microsoft Windows 11"
        )

        ativo.versao = (
            "25H2"
        )

        ativo.cpe = gerar_cpe(
            ativo.produto,
            ativo.versao
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
            "WINDOWS CORRIGIDO"
        )

        print(
            "========================================"
        )

        print(
            "ID:",
            ativo.id
        )

        print(
            "Produto:",
            ativo.produto
        )

        print(
            "Versão:",
            ativo.versao
        )

        print(
            "CPE:",
            ativo.cpe
        )

        print(
            "========================================"
        )

finally:

    db.close()