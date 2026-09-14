import sqlite3


BANCO = "vulnmonitor.db"


conexao = sqlite3.connect(BANCO)

try:

    colunas = conexao.execute(
        "PRAGMA table_info(ativos)"
    ).fetchall()

    nomes = {
        coluna[1]
        for coluna in colunas
    }

    if "build" not in nomes:

        print(
            "Adicionando coluna build..."
        )

        conexao.execute(
            """
            ALTER TABLE ativos
            ADD COLUMN build TEXT
            """
        )

        conexao.commit()

        print(
            "Coluna build adicionada."
        )

    else:

        print(
            "Coluna build já existe."
        )

finally:

    conexao.close()