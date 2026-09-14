from fastapi import (
    APIRouter,
    Request,
    Depends,
    HTTPException
)

from fastapi.responses import (
    HTMLResponse,
    StreamingResponse
)

from fastapi.templating import Jinja2Templates

from sqlalchemy.orm import Session

import csv
import io

from app.database import get_db

from app.services.ativo_service import (
    buscar_ativo,
    contar_ativos
)

from app.services.vulnerabilidades_service import (
    buscar_vulnerabilidades,
    resumir_vulnerabilidades
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates"
)


# =========================================================
# PÁGINA PRINCIPAL
# =========================================================

@router.get(
    "/vulnerabilidades",
    response_class=HTMLResponse
)
async def vulnerabilidades_principal(
    request: Request,
    db: Session = Depends(get_db)
):

    total_ativos = contar_ativos(
        db
    )

    # -----------------------------------------------------
    # Calculamos os totais reais para a página principal.
    # -----------------------------------------------------

    total_vulnerabilidades = 0
    total_criticas = 0

    from app.models import Ativo

    ativos = (
        db.query(
            Ativo
        )
        .all()
    )

    for ativo in ativos:

        vulnerabilidades = (
            buscar_vulnerabilidades(
                db,
                ativo.id
            )
        )

        total_vulnerabilidades += (
            len(
                vulnerabilidades
            )
        )

        resumo = (
            resumir_vulnerabilidades(
                vulnerabilidades
            )
        )

        total_criticas += (
            resumo.get(
                "CRITICAL",
                0
            )
        )

    return templates.TemplateResponse(

        request=request,

        name="vulnerabilidades/index.html",

        context={

            "pagina":
                "vulnerabilidades",

            "total_ativos":
                total_ativos,

            "total_vulnerabilidades":
                total_vulnerabilidades,

            "total_criticas":
                total_criticas
        }
    )


# =========================================================
# VULNERABILIDADES DE UM ATIVO
# =========================================================

@router.get(
    "/vulnerabilidades/{id}",
    response_class=HTMLResponse
)
async def vulnerabilidades_ativo(
    id: int,
    request: Request,
    db: Session = Depends(get_db)
):

    # =====================================================
    # ATIVO
    # =====================================================

    ativo = buscar_ativo(
        db,
        id
    )

    if not ativo:

        raise HTTPException(
            status_code=404,
            detail="Ativo não encontrado"
        )

    # =====================================================
    # VULNERABILIDADES
    # =====================================================

    vulnerabilidades = (
        buscar_vulnerabilidades(
            db,
            ativo.id
        )
    )

    # =====================================================
    # RESUMO
    # =====================================================

    resumo = (
        resumir_vulnerabilidades(
            vulnerabilidades
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
        "DEBUG - VULNERABILIDADES LOCAIS"
    )

    print(
        "========================================"
    )

    print(
        "ATIVO:",
        ativo.nome
    )

    print(
        "PRODUTO:",
        ativo.produto
    )

    print(
        "VERSÃO:",
        ativo.versao
    )

    print(
        "BUILD:",
        getattr(
            ativo,
            "build",
            None
        )
    )

    print(
        "CPE:",
        ativo.cpe
    )

    print(
        "TOTAL VULNERABILIDADES:",
        len(
            vulnerabilidades
        )
    )

    if vulnerabilidades:

        print(
            "PRIMEIRA VULNERABILIDADE:"
        )

        print(
            vulnerabilidades[0]
        )

    else:

        print(
            "NENHUMA VULNERABILIDADE ENCONTRADA."
        )

    print(
        "RESUMO:",
        resumo
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

        name="vulnerabilidades/vulnerabilidades.html",

        context={

            "pagina":
                "vulnerabilidades",

            "ativo":
                ativo,

            "vulnerabilidades":
                vulnerabilidades,

            "resumo":
                resumo
        }
    )


# =========================================================
# EXPORTAR CSV
# =========================================================

@router.get(
    "/vulnerabilidades/{id}/csv"
)
async def exportar_csv(
    id: int,
    db: Session = Depends(get_db)
):

    # =====================================================
    # ATIVO
    # =====================================================

    ativo = buscar_ativo(
        db,
        id
    )

    if not ativo:

        raise HTTPException(
            status_code=404,
            detail="Ativo não encontrado"
        )

    # =====================================================
    # VULNERABILIDADES
    # =====================================================

    vulnerabilidades = (
        buscar_vulnerabilidades(
            db,
            ativo.id
        )
    )

    # =====================================================
    # CSV
    # =====================================================

    output = io.StringIO()

    writer = csv.writer(
        output,
        delimiter=";"
    )

    writer.writerow([
        "CVE",
        "Severidade",
        "CVSS",
        "Publicado",
        "Descrição",
        "URL"
    ])

    for v in vulnerabilidades:

        writer.writerow([

            v.get(
                "cve",
                ""
            ),

            v.get(
                "severidade",
                "UNKNOWN"
            ),

            v.get(
                "cvss",
                0.0
            ),

            v.get(
                "publicado",
                ""
            ),

            v.get(
                "descricao",
                ""
            ),

            v.get(
                "url",
                ""
            )
        ])

    output.seek(
        0
    )

    # =====================================================
    # NOME DO ARQUIVO
    # =====================================================

    nome_arquivo = (
        f"vulnerabilidades_ativo_{id}.csv"
    )

    # =====================================================
    # RESPOSTA
    # =====================================================

    return StreamingResponse(

        iter([
            output.getvalue()
        ]),

        media_type="text/csv",

        headers={
            "Content-Disposition":
                f"attachment; filename={nome_arquivo}"
        }
    )