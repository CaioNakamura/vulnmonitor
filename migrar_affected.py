import sqlite3


BANCO = "vulnmonitor.db"


def obter_colunas(
    conexao,
    tabela
):
    cursor = conexao.execute(
        f"PRAGMA table_info({tabela})"
    )

    return {
        coluna[1]
        for coluna in cursor.fetchall()
    }


def main():

    conexao = sqlite3.connect(
        BANCO
    )

    try:

        print()
        print(
            "========================================"
        )

        print(
            "MIGRAÇÃO DE VULNERABILIDADES"
        )

        print(
            "========================================"
        )

        # -------------------------------------------------
        # ATIVOS
        # -------------------------------------------------

        colunas_ativos = obter_colunas(
            conexao,
            "ativos"
        )

        if "cpe" not in colunas_ativos:

            print(
                "Adicionando coluna ativos.cpe..."
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

        # -------------------------------------------------
        # VULNERABILIDADES
        # -------------------------------------------------

        colunas_vulnerabilidades = (
            obter_colunas(
                conexao,
                "vulnerabilidades"
            )
        )

        # CPEs
        if "cpes" not in colunas_vulnerabilidades:

            print(
                "Adicionando coluna "
                "vulnerabilidades.cpes..."
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

        # AFFECTED
        if "affected" not in colunas_vulnerabilidades:

            print(
                "Adicionando coluna "
                "vulnerabilidades.affected..."
            )

            conexao.execute(
                """
                ALTER TABLE vulnerabilidades
                ADD COLUMN affected TEXT
                """
            )

        else:

            print(
                "vulnerabilidades.affected já existe."
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


if __name__ == "__main__":
    main()