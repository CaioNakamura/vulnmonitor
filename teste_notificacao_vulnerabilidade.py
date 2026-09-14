from app.database import SessionLocal

from app.models import (
    Ativo,
    Vulnerabilidade
)

from app.services.atualizacao_service import (
    montar_email_vulnerabilidade,
    notificar_vulnerabilidade
)

from app.models import AtivoVulnerabilidade


db = SessionLocal()

try:

    print()
    print("========================================")
    print("TESTE DE NOTIFICAÇÃO")
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
            "ERRO: Notebook RH não encontrado."
        )

        raise SystemExit

    print(
        "Ativo:",
        ativo.nome
    )

    print(
        "E-mail:",
        ativo.email_responsavel
    )

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
            "ERRO: CVE-2026-45585 não encontrada."
        )

        raise SystemExit

    print(
        "CVE:",
        vulnerabilidade.cve
    )

    print(
        "Severidade:",
        vulnerabilidade.severidade
    )

    print(
        "CVSS:",
        vulnerabilidade.cvss
    )

    # =====================================================
    # E-MAIL
    # =====================================================

    if not ativo.email_responsavel:

        print(
            "ERRO: ativo sem e-mail."
        )

        raise SystemExit

    assunto, corpo = (
        montar_email_vulnerabilidade(
            ativo,
            vulnerabilidade
        )
    )

    # =====================================================
    # RELACIONAMENTO TEMPORÁRIO
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
            "Criando relacionamento temporário..."
        )

        relacao = AtivoVulnerabilidade(

            ativo_id=
                ativo.id,

            vulnerabilidade_id=
                vulnerabilidade.id,

            notificado=0
        )

        db.add(
            relacao
        )

        db.flush()

    print(
        "Notificado antes:",
        relacao.notificado
    )

    # =====================================================
    # ENVIO
    # =====================================================

    enviado = (
        notificar_vulnerabilidade(
            ativo,
            vulnerabilidade,
            relacao
        )
    )

    # =====================================================
    # SALVAR RESULTADO
    # =====================================================

    db.commit()

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
        "Enviado:",
        enviado
    )

    print(
        "Notificado depois:",
        relacao.notificado
    )

    print(
        "========================================"
    )

finally:

    db.close()