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

        # =================================================
        # DADOS DO WINDOWS
        # =================================================

        ativo.produto = (
            "Microsoft Windows 11"
        )

        ativo.versao = (
            "25H2"
        )

        ativo.build = (
            "26200.9445"
        )

        ativo.cpe = (
            "cpe:2.3:o:microsoft:"
            "windows_11_25h2:"
            "-:*:*:*:*:*:"
            "x64:*"
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
            "WINDOWS 11 ATUALIZADO"
        )

        print(
            "========================================"
        )

        print(
            "ID:",
            ativo.id
        )

        print(
            "Nome:",
            ativo.nome
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
            "Build:",
            ativo.build
        )

        print(
            "CPE:",
            ativo.cpe
        )

        print(
            "========================================"
        )
        print()

finally:

    db.close()