import requests


NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

CPE_ATIVO = (
    "cpe:2.3:o:microsoft:"
    "windows_11_25h2:"
    "-:*:*:*:*:*:x64:*"
)


def main():

    print()
    print("========================================")
    print("DIAGNÓSTICO CPE WINDOWS 11 25H2")
    print("========================================")

    print(
        "CPE consultado:",
        CPE_ATIVO
    )

    resposta = requests.get(
        NVD_API_URL,
        params={
            "cpeName": CPE_ATIVO,
            "resultsPerPage": 10
        },
        timeout=60
    )

    resposta.raise_for_status()

    dados = resposta.json()

    print(
        "Total de candidatos:",
        dados.get(
            "totalResults",
            0
        )
    )

    candidatos = dados.get(
        "vulnerabilities",
        []
    )

    print(
        "Amostra recebida:",
        len(candidatos)
    )

    encontrados = 0

    for item in candidatos:

        cve = item.get(
            "cve",
            {}
        )

        cve_id = cve.get(
            "id",
            ""
        )

        print()
        print(
            "CVE:",
            cve_id
        )

        configurations = cve.get(
            "configurations",
            []
        )

        encontrou_windows = False

        for configuration in configurations:

            for node in configuration.get(
                "nodes",
                []
            ):

                for match in node.get(
                    "cpeMatch",
                    []
                ):

                    criteria = match.get(
                        "criteria",
                        ""
                    ).lower()
                    
                    if (
                        "microsoft:windows_11_25h2"
                        in criteria
                    ):

                        encontrou_windows = True

                        print(
                            "  CPE:",
                            match.get(
                                "criteria"
                            )
                        )

                        print(
                            "  vulnerable:",
                            match.get(
                                "vulnerable"
                            )
                        )

                        print(
                            "  inicio incluindo:",
                            match.get(
                                "versionStartIncluding"
                            )
                        )

                        print(
                            "  inicio excluindo:",
                            match.get(
                                "versionStartExcluding"
                            )
                        )

                        print(
                            "  fim incluindo:",
                            match.get(
                                "versionEndIncluding"
                            )
                        )

                        print(
                            "  fim excluindo:",
                            match.get(
                                "versionEndExcluding"
                            )
                        )

        if encontrou_windows:

            encontrados += 1

        else:

            print(
                "  -> Nenhum match Windows 11 25H2 encontrado."
            )

    print()
    print("========================================")
    print(
        "CVEs da amostra com Windows 11 25H2:",
        encontrados
    )
    print("========================================")


if __name__ == "__main__":
    main()