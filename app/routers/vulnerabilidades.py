from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.ativo_service import buscar_ativo, contar_ativos
from app.services.nvd_service import (
    consultar_vulnerabilidades,
    obter_ultima_atualizacao
)

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


# Página principal do menu "Vulnerabilidades"
@router.get("/vulnerabilidades", response_class=HTMLResponse)
async def vulnerabilidades_principal(
    request: Request,
    db: Session = Depends(get_db)
):

    total_ativos = contar_ativos(db)
    ultima_atualizacao = obter_ultima_atualizacao()

    return templates.TemplateResponse(
        request=request,
        name="vulnerabilidades/index.html",
        context={
            "pagina": "vulnerabilidades",
            "total_ativos": total_ativos,
            "ultima_atualizacao": ultima_atualizacao
        }
    )


# Página de vulnerabilidades de um ativo específico
@router.get("/vulnerabilidades/{id}", response_class=HTMLResponse)
async def vulnerabilidades(
    request: Request,
    id: int,
    db: Session = Depends(get_db)
):

    ativo = buscar_ativo(db, id)

    if not ativo:
        return RedirectResponse("/ativos")

    vulnerabilidades = consultar_vulnerabilidades(
        ativo.fabricante,
        ativo.produto,
        ativo.versao
    )

    return templates.TemplateResponse(
        request=request,
        name="vulnerabilidades/vulnerabilidades.html",
        context={
            "pagina": "vulnerabilidades",
            "ativo": ativo,
            "vulnerabilidades": vulnerabilidades
        }
    )