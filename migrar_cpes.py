import sqlite3


BANCO = "vulnmonitor.db"


def colunas(
    conexao,
    tabela
):

    cursor = conexao.execute(
        f"PRAGMA table_info({tabela})"
    )

    return {
        linha[1]
        for linha in cursor.fetchall()
    }


conexao = sqlite3.connect(
    BANCO
)

try:

    # -----------------------------------------------------
    # ATIVOS
    # -----------------------------------------------------

    colunas_ativos = colunas(
        conexao,
        "ativos"
    )

    if "cpe" not in colunas_ativos:

        print(
            "Adicionando ativos.cpe..."
        )

        conexao.execute(
            """
            ALTER TABLE ativos
            ADD COLUMN cpe TEXT
            """
        )

    else:

        print(
            "ativos.cpe já existe."
        )

    # -----------------------------------------------------
    # VULNERABILIDADES
    # -----------------------------------------------------

    colunas_vulnerabilidades = colunas(
        conexao,
        "vulnerabilidades"
    )

    if "cpes" not in colunas_vulnerabilidades:

        print(
            "Adicionando vulnerabilidades.cpes..."
        )

        conexao.execute(
            """
            ALTER TABLE vulnerabilidades
            ADD COLUMN cpes TEXT
            """
        )

    else:

        print(
            "vulnerabilidades.cpes já existe."
        )

    conexao.commit()

    print()
    print(
        "========================================"
    )

    print(
        "MIGRAÇÃO CONCLUÍDA"
    )

    print(
        "========================================"
    )

finally:

    conexao.close()