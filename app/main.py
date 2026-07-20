from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers.dashboard import router as dashboard_router
from app.routers.ativos import router as ativos_router

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
