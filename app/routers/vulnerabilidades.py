from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.ativo_service import buscar_ativo
from app.services.nvd_service import consultar_vulnerabilidades

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


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