import os
import smtplib

from email.message import EmailMessage


# =========================================================
# CONFIGURAÇÕES SMTP
# =========================================================

SMTP_HOST = os.getenv(
    "VULNMONITOR_SMTP_HOST",
    ""
)

SMTP_PORT = int(
    os.getenv(
        "VULNMONITOR_SMTP_PORT",
        "587"
    )
)

SMTP_USER = os.getenv(
    "VULNMONITOR_SMTP_USER",
    ""
)

SMTP_PASSWORD = os.getenv(
    "VULNMONITOR_SMTP_PASSWORD",
    ""
)

SMTP_FROM = os.getenv(
    "VULNMONITOR_SMTP_FROM",
    SMTP_USER
)


# =========================================================
# ENVIAR E-MAIL
# =========================================================

def enviar_email(
    destinatario: str,
    assunto: str,
    corpo: str
):
    """
    Envia um e-mail usando SMTP.

    As credenciais são obtidas por variáveis
    de ambiente e não ficam no código.
    """

    if not destinatario:

        raise ValueError(
            "Destinatário não informado."
        )

    if not SMTP_HOST:

        raise ValueError(
            "VULNMONITOR_SMTP_HOST não configurado."
        )

    if not SMTP_USER:

        raise ValueError(
            "VULNMONITOR_SMTP_USER não configurado."
        )

    if not SMTP_PASSWORD:

        raise ValueError(
            "VULNMONITOR_SMTP_PASSWORD não configurado."
        )

    mensagem = EmailMessage()

    mensagem["Subject"] = assunto

    mensagem["From"] = SMTP_FROM

    mensagem["To"] = destinatario

    mensagem.set_content(
        corpo
    )

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT,
        timeout=30
    ) as servidor:

        servidor.starttls()

        servidor.login(
            SMTP_USER,
            SMTP_PASSWORD
        )

        servidor.send_message(
            mensagem
        )

    print()
    print(
        "========================================"
    )

    print(
        "E-MAIL ENVIADO"
    )

    print(
        "Destinatário:",
        destinatario
    )

    print(
        "Assunto:",
        assunto
    )

    print(
        "========================================"
    )