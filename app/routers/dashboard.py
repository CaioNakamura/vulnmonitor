from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from sqlalchemy.orm import Session

from app.database import get_db

from app.services.ativo_service import (
    listar_ativos,
    contar_ativos
)

from app.services.vulnerabilidades_service import (
    listar_vulnerabilidades_ativo
)

from app.services.atualizacao_service import (
    obter_ultima_atualizacao
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates"
)


# =========================================================
# DASHBOARD
# =========================================================

@router.get(
    "/",
    response_class=HTMLResponse
)
async def dashboard(
    request: Request,
    db: Session = Depends(get_db)
):

    # =====================================================
    # ATIVOS
    # =====================================================

    total_ativos = contar_ativos(
        db
    )

    ativos = listar_ativos(
        db
    )

    # =====================================================
    # CONTADORES
    # =====================================================

    total_vulnerabilidades = 0

    total_criticas = 0

    total_altas = 0

    total_medias = 0

    total_baixas = 0

    total_unknown = 0

    # =====================================================
    # PERCORRER ATIVOS
    # =====================================================

    for ativo in ativos:

        vulnerabilidades = (
            listar_vulnerabilidades_ativo(
                db,
                ativo.id
            )
        )

        total_vulnerabilidades += len(
            vulnerabilidades
        )

        for vulnerabilidade in vulnerabilidades:

            severidade = (
                getattr(
                    vulnerabilidade,
                    "severidade",
                    None
                )
                or "UNKNOWN"
            ).upper()

            if severidade == "CRITICAL":

                total_criticas += 1

            elif severidade == "HIGH":

                total_altas += 1

            elif severidade == "MEDIUM":

                total_medias += 1

            elif severidade == "LOW":

                total_baixas += 1

            else:

                total_unknown += 1

    # =====================================================
    # ÚLTIMA ATUALIZAÇÃO
    # =====================================================

    ultima_atualizacao = (
        obter_ultima_atualizacao(
            db
        )
    )

    # =====================================================
    # DEBUG
    # =====================================================

    print()
    print(
        "========================================"
    )

    print(
        "DASHBOARD"
    )

    print(
        "========================================"
    )

    print(
        "Total de ativos:",
        total_ativos
    )

    print(
        "Total de vulnerabilidades:",
        total_vulnerabilidades
    )

    print(
        "Total críticas:",
        total_criticas
    )

    print(
        "Total altas:",
        total_altas
    )

    print(
        "Total médias:",
        total_medias
    )

    print(
        "Total baixas:",
        total_baixas
    )

    print(
        "Total unknown:",
        total_unknown
    )

    print(
        "Última atualização:",
        ultima_atualizacao
    )

    print(
        "========================================"
    )
    print()

    # =====================================================
    # RENDERIZAÇÃO
    # =====================================================

    return templates.TemplateResponse(

        request=request,

        name="dashboard/dashboard.html",

        context={

            "pagina":
                "dashboard",

            "total_ativos":
                total_ativos,

            "total_vulnerabilidades":
                total_vulnerabilidades,

            "total_criticas":
                total_criticas,

            "total_altas":
                total_altas,

            "total_medias":
                total_medias,

            "total_baixas":
                total_baixas,

            "total_unknown":
                total_unknown,

            "ultima_atualizacao":
                ultima_atualizacao
        }
    )