import sqlite3
import json


BANCO = "vulnmonitor.db"

conexao = sqlite3.connect(BANCO)

try:

    registros = conexao.execute(
        """
        SELECT cve, cpes
        FROM vulnerabilidades
        WHERE cpes IS NOT NULL
        LIMIT 5
        """
    ).fetchall()

    print()
    print("========================================")
    print("CPEs ARMAZENADOS")
    print("========================================")

    for cve, cpes in registros:

        print()
        print("CVE:", cve)

        try:

            dados = json.loads(
                cpes
            )

            print(
                "Quantidade de CPEs:",
                len(dados)
            )

            for item in dados[:5]:

                if isinstance(
                    item,
                    dict
                ):

                    print(
                        "criteria:",
                        item.get("criteria")
                    )

                else:

                    print(
                        "CPE:",
                        item
                    )

        except Exception as erro:

            print(
                "Erro ao ler JSON:",
                erro
            )

    print()
    print("========================================")

finally:

    conexao.close()