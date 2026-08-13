from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.database import Base, engine
from app.models import Empresa, Ativo
from app.routers.dashboard import router as dashboard_router
from app.routers.ativos import router as ativos_router
from app.routers.vulnerabilidades import router as vulnerabilidades_router


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnMonitor",
    version="1.0.0"
)

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static"
)

app.include_router(dashboard_router)
app.include_router(ativos_router)
app.include_router(vulnerabilidades_router)