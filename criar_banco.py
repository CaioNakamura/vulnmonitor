from app.database import Base, engine
from app.models import Ativo

Base.metadata.create_all(bind=engine)

print("Banco criado com sucesso!")