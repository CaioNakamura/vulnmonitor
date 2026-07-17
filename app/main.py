from fastapi import FastAPI

app = FastAPI(
    title="VulnMonitor",
    description="Sistema de Monitoramento Automatizado de Vulnerabilidades Tecnológicas",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "projeto": "VulnMonitor",
        "status": "online",
        "versao": "1.0.0"
    }
