from app.database import engine
from app.models import Atualizacao


print("========================================")
print("CRIANDO TABELA DE ATUALIZAÇÕES")
print("========================================")


Atualizacao.__table__.create(
    bind=engine,
    checkfirst=True
)


print("Tabela 'atualizacoes' criada/verificada.")
print("========================================")