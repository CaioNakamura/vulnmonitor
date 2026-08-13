from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.ativo_service import buscar_ativo, contar_ativos
from app.services.nvd_service import (
    resumir_vulnerabilidades,
    obter_ultima_atualizacao
)
from app.services.vulnerabilidades_service import (
    buscar_vulnerabilidades,
    salvar_vulnerabilidades
)

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


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
            "total_vulnerabilidades": 0,
            "total_criticas": 0,
            "ultima_atualizacao": ultima_atualizacao
        }
    )


@router.get("/vulnerabilidades/{id}", response_class=HTMLResponse)
async def vulnerabilidades_ativo(
    id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    ativo = buscar_ativo(db, id)

    if not ativo:
        raise HTTPException(
            status_code=404,
            detail="Ativo não encontrado"
        )

    vulnerabilidades = buscar_vulnerabilidades(ativo)

    salvar_vulnerabilidades(
        db,
        ativo.id,
        vulnerabilidades
    )

    resumo = resumir_vulnerabilidades(vulnerabilidades)

    return templates.TemplateResponse(
        request=request,
        name="vulnerabilidades/vulnerabilidades.html",
        context={
            "pagina": "vulnerabilidades",
            "ativo": ativo,
            "vulnerabilidades": vulnerabilidades,
            "resumo": resumo
        }
    )


# =========================================================
# Exportar CSV das vulnerabilidades do ativo
# =========================================================
@router.get("/vulnerabilidades/{id}/csv")
async def exportar_csv(
    id: int,
    db: Session = Depends(get_db)
):
    import csv
    import io
    from fastapi.responses import StreamingResponse

    ativo = buscar_ativo(db, id)

    if not ativo:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")

    vulnerabilidades = buscar_vulnerabilidades(ativo)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')

    # Cabeçalho
    writer.writerow([
        "CVE",
        "Severidade",
        "CVSS",
        "Publicado",
        "Descrição"
    ])

    # Dados
    for v in vulnerabilidades:
        writer.writerow([
            v["id"],
            v["severidade"],
            v["cvss"],
            v["publicado"],
            v["descricao"]
        ])

    output.seek(0)

    nome_arquivo = f"vulnerabilidades_ativo_{id}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={nome_arquivo}"
        }
    )