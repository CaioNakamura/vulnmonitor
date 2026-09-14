from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.services.atualizacao_service import (
    consultar_nvd_periodo,
    salvar_cve,
    ativo_e_afetado,
    relacionar_ativo
)

from app.models import Ativo


# =========================================================
# CONFIGURAÇÃO
# =========================================================

DIAS_INICIAIS = 30


# =========================================================
# CARGA INICIAL
# =========================================================

def main():

    fim = datetime.now(timezone.utc)

    inicio = (
        fim
        - timedelta(
            days=DIAS_INICIAIS
        )
    )

    db = SessionLocal()

    try:

        print()
        print("========================================")
        print("CARGA INICIAL DA NVD")
        print("========================================")
        print(
            "Período:",
            inicio,
            "até",
            fim
        )
        print(
            "Dias:",
            DIAS_INICIAIS
        )

        # -------------------------------------------------
        # Consulta NVD
        # -------------------------------------------------

        vulnerabilidades = consultar_nvd_periodo(
            inicio,
            fim
        )

        print()
        print(
            "CVEs recebidas:",
            len(vulnerabilidades)
        )

        # -------------------------------------------------
        # Ativos
        # -------------------------------------------------

        ativos = (
            db.query(
                Ativo
            )
            .all()
        )

        print(
            "Ativos cadastrados:",
            len(ativos)
        )

        novas_cves = 0
        novos_relacionamentos = 0

        # -------------------------------------------------
        # Processamento
        # -------------------------------------------------

        for dados_cve in vulnerabilidades:

            vulnerabilidade, nova = salvar_cve(
                db,
                dados_cve
            )

            if nova:

                novas_cves += 1

            for ativo in ativos:

                if ativo_e_afetado(
                    ativo,
                    dados_cve
                ):

                    criada = relacionar_ativo(
                        db,
                        ativo,
                        vulnerabilidade
                    )

                    if criada:

                        novos_relacionamentos += 1

        db.commit()

        print()
        print("========================================")
        print("CARGA INICIAL CONCLUÍDA")
        print("========================================")
        print(
            "CVEs recebidas:",
            len(vulnerabilidades)
        )
        print(
            "CVEs novas:",
            novas_cves
        )
        print(
            "Relacionamentos:",
            novos_relacionamentos
        )
        print("========================================")

    except Exception as erro:

        db.rollback()

        print()
        print("========================================")
        print("ERRO NA CARGA INICIAL")
        print("========================================")
        print(erro)
        print("========================================")

        raise

    finally:

        db.close()


if __name__ == "__main__":
    main()