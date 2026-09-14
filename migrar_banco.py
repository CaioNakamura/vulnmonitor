import sqlite3
from pathlib import Path


BANCO = Path("vulnmonitor.db")


if not BANCO.exists():
    print("ERRO: vulnmonitor.db não encontrado.")
    exit()


conexao = sqlite3.connect(BANCO)
cursor = conexao.cursor()


print("========================================")
print("INICIANDO MIGRAÇÃO")
print("========================================")


# =========================================================
# 1. BACKUP DA TABELA ANTIGA
# =========================================================

print("\nCriando backup da tabela antiga...")


cursor.execute("""
    DROP TABLE IF EXISTS vulnerabilidades_antigas
""")


cursor.execute("""
    CREATE TABLE vulnerabilidades_antigas AS
    SELECT *
    FROM vulnerabilidades
""")


print("Backup criado com sucesso.")


# =========================================================
# 2. RENOMEIA A TABELA ANTIGA
# =========================================================

print("\nRenomeando tabela antiga...")


cursor.execute("""
    ALTER TABLE vulnerabilidades
    RENAME TO vulnerabilidades_antigas_original
""")


# =========================================================
# 3. CRIA NOVA TABELA DE VULNERABILIDADES
# =========================================================

print("Criando nova tabela vulnerabilidades...")


cursor.execute("""
    CREATE TABLE vulnerabilidades (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        cve VARCHAR NOT NULL UNIQUE,

        descricao VARCHAR,

        severidade VARCHAR,

        cvss FLOAT,

        publicado VARCHAR,

        url VARCHAR,

        criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")


# =========================================================
# 4. IMPORTA CVEs ÚNICAS
# =========================================================

print("\nImportando CVEs únicas...")


cursor.execute("""
    INSERT OR IGNORE INTO vulnerabilidades
    (
        cve,
        descricao,
        severidade,
        cvss,
        publicado,
        url,
        criado_em
    )

    SELECT
        cve,
        descricao,
        severidade,
        cvss,
        publicado,
        url,
        criado_em

    FROM vulnerabilidades_antigas_original

    WHERE ativo_id IN (2, 3, 4)

    GROUP BY cve
""")


print(
    "CVEs importadas:",
    cursor.rowcount
)


# =========================================================
# 5. CRIA TABELA DE RELACIONAMENTO
# =========================================================

print("\nCriando tabela ativo_vulnerabilidades...")


cursor.execute("""
    CREATE TABLE IF NOT EXISTS ativo_vulnerabilidades (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        ativo_id INTEGER NOT NULL,

        vulnerabilidade_id INTEGER NOT NULL,

        detectada_em DATETIME DEFAULT CURRENT_TIMESTAMP,

        notificado INTEGER DEFAULT 0,

        FOREIGN KEY (
            ativo_id
        )
        REFERENCES ativos(id),

        FOREIGN KEY (
            vulnerabilidade_id
        )
        REFERENCES vulnerabilidades(id),

        UNIQUE (
            ativo_id,
            vulnerabilidade_id
        )
    )
""")


# =========================================================
# 6. CRIA RELACIONAMENTOS
# =========================================================

print("\nCriando relacionamentos...")


cursor.execute("""
    INSERT OR IGNORE INTO ativo_vulnerabilidades
    (
        ativo_id,
        vulnerabilidade_id
    )

    SELECT DISTINCT

        antiga.ativo_id,

        nova.id

    FROM vulnerabilidades_antigas_original antiga

    INNER JOIN vulnerabilidades nova

        ON nova.cve = antiga.cve

    WHERE antiga.ativo_id IN (2, 3, 4)
""")


print(
    "Relacionamentos criados:",
    cursor.rowcount
)


# =========================================================
# 7. ÍNDICES
# =========================================================

cursor.execute("""
    CREATE INDEX IF NOT EXISTS
    idx_ativo_vulnerabilidades_ativo
    ON ativo_vulnerabilidades(ativo_id)
""")


cursor.execute("""
    CREATE INDEX IF NOT EXISTS
    idx_ativo_vulnerabilidades_vuln
    ON ativo_vulnerabilidades(vulnerabilidade_id)
""")


# =========================================================
# 8. FINALIZA
# =========================================================

conexao.commit()


print("\n========================================")
print("MIGRAÇÃO CONCLUÍDA")
print("========================================")


# Quantidade de CVEs
cursor.execute("""
    SELECT COUNT(*)
    FROM vulnerabilidades
""")


total_cves = cursor.fetchone()[0]


# Quantidade de relações
cursor.execute("""
    SELECT COUNT(*)
    FROM ativo_vulnerabilidades
""")


total_relacoes = cursor.fetchone()[0]


print(
    f"CVEs únicas: {total_cves}"
)


print(
    f"Relações ativo ↔ CVE: {total_relacoes}"
)


# Distribuição
print("\nDistribuição por ativo:")


cursor.execute("""
    SELECT
        ativo_id,
        COUNT(*)
    FROM ativo_vulnerabilidades
    GROUP BY ativo_id
    ORDER BY ativo_id
""")


for ativo_id, quantidade in cursor.fetchall():

    print(
        f"Ativo {ativo_id}: {quantidade}"
    )


print("\n========================================")
print("TABELA ANTIGA PRESERVADA")
print("========================================")


cursor.execute("""
    SELECT COUNT(*)
    FROM vulnerabilidades_antigas_original
""")


print(
    "Registros antigos:",
    cursor.fetchone()[0]
)


conexao.close()