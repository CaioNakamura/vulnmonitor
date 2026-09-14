from app.database import SessionLocal
from app.models import AtivoVulnerabilidade


ATIVO_ID = 2


db = SessionLocal()

try:

    registros = (
        db.query(
            AtivoVulnerabilidade
        )
        .filter(
            AtivoVulnerabilidade.ativo_id == ATIVO_ID
        )
        .all()
    )

    print()
    print("========================================")
    print("LIMPANDO RELACIONAMENTOS DO WINDOWS")
    print("========================================")

    print(
        "Relacionamentos encontrados:",
        len(registros)
    )

    for registro in registros:
        db.delete(registro)

    db.commit()

    print(
        "Relacionamentos removidos:",
        len(registros)
    )

    print("========================================")

finally:

    db.close()