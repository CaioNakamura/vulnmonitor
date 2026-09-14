import json

from app.database import SessionLocal

from app.models import Vulnerabilidade


def main():

    db = SessionLocal()

    try:

        vulnerabilidades = (
            db.query(
                Vulnerabilidade
            )
            .all()
        )

        total_cves = len(
            vulnerabilidades
        )

        encontradas_windows = []

        for v in vulnerabilidades:

            try:

                cpes = json.loads(
                    v.cpes or "[]"
                )

            except Exception:

                cpes = []

            for cpe in cpes:

                if isinstance(
                    cpe,
                    dict
                ):

                    criteria = cpe.get(
                        "criteria",
                        ""
                    )

                else:

                    criteria = str(
                        cpe
                    )

                criteria = criteria.lower()

                if (
                    "microsoft:windows_11"
                    in criteria
                ):

                    encontradas_windows.append(
                        (
                            v.cve,
                            criteria
                        )
                    )

        print()
        print(
            "========================================"
        )

        print(
            "DIAGNÓSTICO WINDOWS 11"
        )

        print(
            "========================================"
        )

        print(
            "Total de CVEs no banco:",
            total_cves
        )

        print(
            "CPEs Windows 11 encontrados:",
            len(
                encontradas_windows
            )
        )

        for cve, criteria in (
            encontradas_windows[:30]
        ):

            print()
            print(
                "CVE:",
                cve
            )

            print(
                "CPE:",
                criteria
            )

        print()
        print(
            "========================================"
        )

    finally:

        db.close()


if __name__ == "__main__":

    main()