import json

from app.database import SessionLocal
from app.models import Vulnerabilidade


def main():

    db = SessionLocal()

    try:

        registros = (
            db.query(Vulnerabilidade)
            .all()
        )

        encontrados = 0

        print()
        print("========================================")
        print("WINDOWS 11 - DADOS ARMAZENADOS")
        print("========================================")

        for v in registros:

            try:
                cpes = json.loads(
                    v.cpes or "[]"
                )
            except Exception:
                cpes = []

            try:
                affected = json.loads(
                    v.affected or "[]"
                )
            except Exception:
                affected = []

            tem_windows = False

            for cpe in cpes:

                if isinstance(cpe, dict):
                    criteria = cpe.get(
                        "criteria",
                        ""
                    )
                else:
                    criteria = str(cpe)

                if (
                    "windows_11_25h2"
                    in criteria.lower()
                ):

                    print()
                    print("CVE:", v.cve)
                    print("CPE:", criteria)

                    tem_windows = True
                    encontrados += 1

            for item in affected:

                texto = (
                    str(item.get("vendor", ""))
                    + " "
                    + str(item.get("product", ""))
                ).lower()

                if "windows 11" in texto:

                    print()
                    print(
                        "AFFECTED:",
                        v.cve
                    )

                    print(
                        "Produto:",
                        item.get("product")
                    )

                    for versao in item.get(
                        "versions",
                        []
                    ):

                        print(
                            "Versão:",
                            versao
                        )

                    tem_windows = True

        print()
        print("========================================")
        print(
            "Registros Windows encontrados:",
            encontrados
        )
        print("========================================")

    finally:

        db.close()


if __name__ == "__main__":
    main()