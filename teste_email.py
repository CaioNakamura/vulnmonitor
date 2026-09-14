from app.services.email_service import enviar_email


DESTINATARIO = "n8nprojeto.2026@gmail.com"


enviar_email(
    destinatario=DESTINATARIO,
    assunto="[VulnMonitor] Teste de notificação",
    corpo="""
Este é um teste do sistema VulnMonitor.

O serviço de notificações por e-mail está funcionando.

Este e-mail ainda não foi disparado por uma vulnerabilidade real.
"""
)

print(
    "TESTE DE E-MAIL CONCLUÍDO."
)