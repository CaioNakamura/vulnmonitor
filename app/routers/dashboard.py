from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.ativo_service import listar_ativos, contar_ativos
from app.services.nvd_service import (
    consultar_vulnerabilidades,
    obter_ultima_atualizacao
)

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: Session = Depends(get_db)
):

    total_ativos = contar_ativos(db)

    ativos = listar_ativos(db)

    total_vulnerabilidades = 0
    total_criticas = 0
    total_altas = 0

    for ativo in ativos:

        vulnerabilidades = consultar_vulnerabilidades(
            ativo.produto,
            ativo.versao
        )

        total_vulnerabilidades += len(vulnerabilidades)

        for item in vulnerabilidades:

            severidade = item.get("severidade", "").upper()

            if severidade == "CRITICAL":
                total_criticas += 1

            elif severidade == "HIGH":
                total_altas += 1

    ultima_atualizacao = obter_ultima_atualizacao()

    return templates.TemplateResponse(
        request=request,
        name="dashboard/dashboard.html",
        context={
            "pagina": "dashboard",
            "total_ativos": total_ativos,
            "total_vulnerabilidades": total_vulnerabilidades,
            "ultima_atualizacao": ultima_atualizacao
        }
    )