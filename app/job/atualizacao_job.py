from apscheduler.schedulers.background import BackgroundScheduler

from app.database import SessionLocal
from app.services.atualizacao_service import executar_atualizacao


# =========================================================
# EXECUÇÃO DA ATUALIZAÇÃO
# =========================================================

def executar_job_atualizacao():
    """
    Executa a atualização automática da NVD.

    Uma nova sessão do banco é criada exclusivamente
    para a execução do job.
    """

    print()
    print("========================================")
    print("JOB AUTOMÁTICO - ATUALIZAÇÃO NVD")
    print("========================================")

    db = SessionLocal()

    try:
        resultado = executar_atualizacao(db)

        print()
        print("JOB FINALIZADO COM SUCESSO")
        print("Resultado:", resultado)
        print("========================================")

    except Exception as erro:

        print()
        print("ERRO NO JOB AUTOMÁTICO:")
        print(erro)
        print("========================================")

    finally:
        db.close()


# =========================================================
# AGENDADOR
# =========================================================

scheduler = BackgroundScheduler(
    timezone="America/Sao_Paulo"
)


def iniciar_agendador():
    """
    Inicia o agendador da aplicação.

    A atualização será executada todos os dias
    às 05:00 da manhã.
    """

    if scheduler.running:
        return

    scheduler.add_job(
        executar_job_atualizacao,
        trigger="cron",
        hour=5,
        minute=0,
        id="atualizacao_nvd_diaria",
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    scheduler.start()

    print()
    print("========================================")
    print("AGENDADOR INICIADO")
    print("Próxima atualização automática: 05:00")
    print("========================================")


def parar_agendador():
    """
    Encerra o agendador quando a aplicação for finalizada.
    """

    if scheduler.running:
        scheduler.shutdown(wait=False)

        print()
        print("AGENDADOR ENCERRADO")