from contextlib import asynccontextmanager

from fastapi import FastAPI

from fastapi.staticfiles import (
    StaticFiles
)

from app.models import (
    Empresa,
    Ativo,
    Vulnerabilidade,
    AtivoVulnerabilidade,
    Atualizacao
)

from app.routers.dashboard import (
    router as dashboard_router
)

from app.routers.ativos import (
    router as ativos_router
)

from app.routers.vulnerabilidades import (
    router as vulnerabilidades_router
)

from app.job.atualizacao_job import (
    iniciar_agendador,
    parar_agendador
)


# =========================================================
# CICLO DE VIDA
# =========================================================

@asynccontextmanager
async def lifespan(
    app: FastAPI
):

    print()
    print(
        "========================================"
    )

    print(
        "INICIANDO VULNMONITOR"
    )

    print(
        "========================================"
    )

    iniciar_agendador()

    yield

    parar_agendador()


# =========================================================
# APLICAÇÃO
# =========================================================

app = FastAPI(

    title="VulnMonitor",

    version="1.0.0",

    lifespan=lifespan
)


# =========================================================
# STATIC
# =========================================================

app.mount(

    "/static",

    StaticFiles(
        directory="app/static"
    ),

    name="static"
)


# =========================================================
# ROTAS
# =========================================================

app.include_router(
    dashboard_router
)

app.include_router(
    ativos_router
)

app.include_router(
    vulnerabilidades_router
)