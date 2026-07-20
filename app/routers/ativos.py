from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


@router.get("/ativos", response_class=HTMLResponse)
async def ativos(request: Request):

    return templates.TemplateResponse(
        "ativos/ativos.html",
        {
            "request": request
        }
    )