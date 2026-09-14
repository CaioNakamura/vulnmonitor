import json
import time

import requests

from app.database import SessionLocal
from app.models import Vulnerabilidade

from app.services.atualizacao_service import (
    extrair_cpe_matches,
    extrair_affected,
)


NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

INTERVALO = 6
MAX_TENTATIVAS = 3


def consultar_cve(cve_id):

    parametros = {
        "cveId": cve_id
    }

    for tentativa in range(
        1,
        MAX_TENTATIVAS + 1
    ):

        try:

            resposta = requests.get(
                NVD_API_URL,
                params=parametros,
                timeout=60
            )

            if resposta.status_code == 429:

                espera = 15 * tentativa

                print(
                    f"HTTP 429 para {cve_id}. "
                    f"Aguardando {espera}s..."
                )

                time.sleep(
                    espera
                )

                continue

            resposta.raise_for_status()

            dados = resposta.json()

            vulnerabilidades = (
                dados.get(
                    "vulnerabilities",
                    []
                )
            )

            if not vulnerabilidades:

                return None

            return vulnerabilidades[0].get(
                "cve",
                {}
            )

        except requests.exceptions.RequestException as erro:

            if tentativa >= MAX_TENTATIVAS:

                print(
                    f"Erro definitivo em {cve_id}:",
                    erro
                )

                return None

            espera = 10 * tentativa

            print(
                f"Erro ao consultar {cve_id}. "
                f"Tentando novamente em {espera}s..."
            )

            time.sleep(
                espera
            )

    return None


def main():

    db = SessionLocal()

    try:

        registros = (
            db.query(
                Vulnerabilidade
            )
            .order_by(
                Vulnerabilidade.id.asc()
            )
            .all()
        )

        total = len(
            registros
        )

        print()
        print(
            "========================================"
        )
        print(
            "ATUALIZANDO DADOS DAS CVEs"
        )
        print(
            "========================================"
        )

        print(
            "CVEs encontradas no banco:",
            total
        )

        atualizadas = 0
        com_cpe = 0
        com_affected = 0
        erros = 0

        for indice, registro in enumerate(
            registros,
            start=1
        ):

            print()
            print(
                f"[{indice}/{total}] "
                f"{registro.cve}"
            )

            cve = consultar_cve(
                registro.cve
            )

            if not cve:

                print(
                    "Não foi possível obter a CVE."
                )

                erros += 1

                continue

            cpes = (
                extrair_cpe_matches(
                    cve
                )
            )

            affected = (
                extrair_affected(
                    cve
                )
            )

            registro.cpes = json.dumps(
                cpes,
                ensure_ascii=False
            )

            registro.affected = json.dumps(
                affected,
                ensure_ascii=False
            )

            if cpes:

                com_cpe += 1

            if affected:

                com_affected += 1

            atualizadas += 1

            print(
                "CPEs:",
                len(cpes)
            )

            print(
                "AFFECTED:",
                len(affected)
            )

            # Salva em blocos para não perder
            # todo o progresso caso ocorra erro.
            if indice % 10 == 0:

                db.commit()

                print(
                    "Progresso salvo no banco."
                )

            time.sleep(
                INTERVALO
            )

        db.commit()

        print()
        print(
            "========================================"
        )
        print(
            "ATUALIZAÇÃO CONCLUÍDA"
        )
        print(
            "========================================"
        )

        print(
            "Total:",
            total
        )

        print(
            "Atualizadas:",
            atualizadas
        )

        print(
            "Com CPE:",
            com_cpe
        )

        print(
            "Com AFFECTED:",
            com_affected
        )

        print(
            "Erros:",
            erros
        )

        print(
            "========================================"
        )

    except Exception as erro:

        db.rollback()

        print()
        print(
            "========================================"
        )
        print(
            "ERRO"
        )
        print(
            "========================================"
        )

        print(
            erro
        )

        raise

    finally:

        db.close()


if __name__ == "__main__":

    main()