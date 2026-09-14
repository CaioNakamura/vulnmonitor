from fastapi import (
    APIRouter,
    Request,
    Depends,
    Form
)

from fastapi.responses import (
    HTMLResponse,
    RedirectResponse
)

from fastapi.templating import (
    Jinja2Templates
)

from sqlalchemy.orm import Session

from app.database import get_db

from app.services.ativo_service import (
    listar_ativos,
    cadastrar_ativo,
    editar_ativo,
    excluir_ativo
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates"
)


# =========================================================
# LISTAR ATIVOS
# =========================================================

@router.get(
    "/ativos",
    response_class=HTMLResponse
)
async def ativos(
    request: Request,
    db: Session = Depends(get_db)
):

    lista = listar_ativos(
        db
    )

    return templates.TemplateResponse(

        request=request,

        name="ativos/ativos.html",

        context={
            "pagina": "ativos",
            "ativos": lista
        }
    )


# =========================================================
# NOVO ATIVO
# =========================================================

@router.post(
    "/ativos/novo"
)
async def novo_ativo(

    nome: str = Form(...),

    produto: str = Form(...),

    versao: str = Form(...),

    build: str = Form(""),

    email_responsavel: str = Form(""),

    db: Session = Depends(get_db)
):

    cadastrar_ativo(

        db,

        nome,

        produto,

        versao,

        build,

        email_responsavel
    )

    return RedirectResponse(
        "/ativos",
        status_code=303
    )


# =========================================================
# EDITAR ATIVO
# =========================================================

@router.post(
    "/ativos/editar/{id}"
)
async def editar(

    id: int,

    nome: str = Form(...),

    produto: str = Form(...),

    versao: str = Form(...),

    build: str = Form(""),

    email_responsavel: str = Form(""),

    db: Session = Depends(get_db)

):

    editar_ativo(

        db,

        id,

        nome,

        produto,

        versao,

        build,

        email_responsavel
    )

    return RedirectResponse(
        "/ativos",
        status_code=303
    )


# =========================================================
# EXCLUIR ATIVO
# =========================================================

@router.get(
    "/ativos/excluir/{id}"
)
async def excluir(

    id: int,

    db: Session = Depends(get_db)
):

    excluir_ativo(
        db,
        id
    )

    return RedirectResponse(
        "/ativos",
        status_code=303
    )