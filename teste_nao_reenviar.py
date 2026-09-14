from app.database import SessionLocal

from app.models import (
    Ativo,
    Vulnerabilidade,
    AtivoVulnerabilidade
)

from app.services.atualizacao_service import (
    relacionar_ativo
)


db = SessionLocal()

try:

    print()
    print("========================================")
    print("TESTE DE NÃO REENVIO")
    print("========================================")

    # =====================================================
    # ATIVO
    # =====================================================

    ativo = (
        db.query(
            Ativo
        )
        .filter(
            Ativo.id == 2
        )
        .first()
    )

    if not ativo:

        print(
            "Ativo ID 2 não encontrado."
        )

        raise SystemExit

    # =====================================================
    # VULNERABILIDADE
    # =====================================================

    vulnerabilidade = (
        db.query(
            Vulnerabilidade
        )
        .filter(
            Vulnerabilidade.cve
            ==
            "CVE-2026-45585"
        )
        .first()
    )

    if not vulnerabilidade:

        print(
            "CVE-2026-45585 não encontrada."
        )

        raise SystemExit

    # =====================================================
    # RELACIONAMENTO
    # =====================================================

    relacao = (
        db.query(
            AtivoVulnerabilidade
        )
        .filter(
            AtivoVulnerabilidade.ativo_id
            ==
            ativo.id,

            AtivoVulnerabilidade.vulnerabilidade_id
            ==
            vulnerabilidade.id
        )
        .first()
    )

    if not relacao:

        print(
            "Relacionamento não encontrado."
        )

        raise SystemExit

    print(
        "Ativo:",
        ativo.nome
    )

    print(
        "CVE:",
        vulnerabilidade.cve
    )

    print(
        "Notificado antes:",
        relacao.notificado
    )

    # =====================================================
    # TESTE
    # =====================================================

    resultado = relacionar_ativo(
        db,
        ativo,
        vulnerabilidade,
        notificar=True
    )

    # =====================================================
    # SALVAR
    # =====================================================

    db.commit()

    # =====================================================
    # CONSULTAR NOVAMENTE
    # =====================================================

    relacao = (
        db.query(
            AtivoVulnerabilidade
        )
        .filter(
            AtivoVulnerabilidade.ativo_id
            ==
            ativo.id,

            AtivoVulnerabilidade.vulnerabilidade_id
            ==
            vulnerabilidade.id
        )
        .first()
    )

    print()
    print(
        "========================================"
    )

    print(
        "RESULTADO"
    )

    print(
        "========================================"
    )

    print(
        "Retorno da função:",
        resultado
    )

    print(
        "Notificado depois:",
        relacao.notificado
    )

    if relacao.notificado == 1:

        print()
        print(
            "OK: a vulnerabilidade continua "
            "marcada como já notificada."
        )

        print(
            "Nenhum novo envio deveria ocorrer."
        )

    else:

        print()
        print(
            "ATENÇÃO: notificado voltou para 0."
        )

    print(
        "========================================"
    )

finally:

    db.close()