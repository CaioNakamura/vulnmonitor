from app.database import SessionLocal
from app.models import Ativo

session = SessionLocal()

novo_ativo = Ativo(
    nome="Notebook RH",
    fabricante="Microsoft",
    produto="Windows",
    versao="11"
)

session.add(novo_ativo)
session.commit()

print("Ativo cadastrado com sucesso!")

session.close()