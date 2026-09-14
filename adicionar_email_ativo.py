import sqlite3


BANCO = "vulnmonitor.db"


conexao = sqlite3.connect(
    BANCO
)

try:

    colunas = conexao.execute(
        "PRAGMA table_info(ativos)"
    ).fetchall()

    nomes = {
        coluna[1]
        for coluna in colunas
    }

    if "email_responsavel" not in nomes:

        print(
            "Adicionando coluna email_responsavel..."
        )

        conexao.execute(
            """
            ALTER TABLE ativos
            ADD COLUMN email_responsavel TEXT
            """
        )

        conexao.commit()

        print(
            "Coluna adicionada com sucesso."
        )

    else:

        print(
            "Coluna email_responsavel já existe."
        )

finally:

    conexao.close()