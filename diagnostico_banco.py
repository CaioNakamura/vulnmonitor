import sqlite3


BANCO = "vulnmonitor.db"


conexao = sqlite3.connect(BANCO)

try:

    # =====================================================
    # TOTAL DE CVEs
    # =====================================================

    total_cves = conexao.execute(
        "SELECT COUNT(*) FROM vulnerabilidades"
    ).fetchone()[0]

    # =====================================================
    # CVEs COM CPE
    # =====================================================

    com_cpe = conexao.execute(
        """
        SELECT COUNT(*)
        FROM vulnerabilidades
        WHERE cpes IS NOT NULL
        """
    ).fetchone()[0]

    # =====================================================
    # CVEs COM AFFECTED
    # =====================================================

    com_affected = conexao.execute(
        """
        SELECT COUNT(*)
        FROM vulnerabilidades
        WHERE affected IS NOT NULL
        """
    ).fetchone()[0]

    # =====================================================
    # RELACIONAMENTOS
    # =====================================================

    relacionamentos = conexao.execute(
        """
        SELECT COUNT(*)
        FROM ativo_vulnerabilidades
        """
    ).fetchone()[0]

    # =====================================================
    # RESULTADO
    # =====================================================

    print()
    print("========================================")
    print("DIAGNÓSTICO DO BANCO")
    print("========================================")

    print(
        "Total CVEs:",
        total_cves
    )

    print(
        "CVEs com CPE:",
        com_cpe
    )

    print(
        "CVEs com AFFECTED:",
        com_affected
    )

    print(
        "Relacionamentos:",
        relacionamentos
    )

    print("========================================")

finally:

    conexao.close()