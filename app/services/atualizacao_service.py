from datetime import datetime, timedelta, timezone
import json
import re
import time

import requests

from sqlalchemy.orm import Session

from app.models import (
    Ativo,
    Vulnerabilidade,
    AtivoVulnerabilidade,
    Atualizacao
)

from app.services.email_service import enviar_email


# =========================================================
# CONFIGURAÇÕES
# =========================================================

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

RESULTADOS_POR_PAGINA = 200

PRIMEIRO_INTERVALO_DIAS = 1

INTERVALO_ENTRE_PAGINAS = 6

MAX_TENTATIVAS = 3


# =========================================================
# ÚLTIMA ATUALIZAÇÃO
# =========================================================

def obter_ultima_atualizacao(
    db: Session
):
    """
    Retorna a última atualização concluída.
    """

    return (
        db.query(
            Atualizacao
        )
        .filter(
            Atualizacao.status == "CONCLUIDA"
        )
        .order_by(
            Atualizacao.finalizada_em.desc()
        )
        .first()
    )


# =========================================================
# DEFINIR PERÍODO DA ATUALIZAÇÃO
# =========================================================

def definir_periodo_atualizacao(
    db: Session
):
    """
    Define o intervalo que será consultado na NVD.
    """

    ultima = obter_ultima_atualizacao(
        db
    )

    agora = datetime.now(
        timezone.utc
    )

    if (
        ultima
        and
        ultima.finalizada_em
    ):

        inicio = (
            ultima.finalizada_em
        )

        if inicio.tzinfo is None:

            inicio = inicio.replace(
                tzinfo=timezone.utc
            )

    else:

        inicio = (
            agora
            -
            timedelta(
                days=PRIMEIRO_INTERVALO_DIAS
            )
        )

    return inicio, agora


# =========================================================
# FORMATAR DATA NVD
# =========================================================

def formatar_data_nvd(
    data
):
    """
    Converte data ISO da NVD para DD/MM/AAAA.
    """

    if not data:

        return ""

    try:

        return datetime.fromisoformat(
            data.replace(
                "Z",
                "+00:00"
            )
        ).strftime(
            "%d/%m/%Y"
        )

    except Exception:

        return str(data)[:10]


# =========================================================
# EXTRAIR DESCRIÇÃO
# =========================================================

def extrair_descricao(
    cve
):
    """
    Obtém a descrição em inglês.
    """

    for descricao in cve.get(
        "descriptions",
        []
    ):

        if descricao.get(
            "lang"
        ) == "en":

            return descricao.get(
                "value",
                "Sem descrição"
            )

    return "Sem descrição"


# =========================================================
# EXTRAIR CVSS
# =========================================================

def extrair_cvss(
    cve
):
    """
    Prioridade:

        CVSS 4.0
        CVSS 3.1
        CVSS 3.0
        CVSS 2.0
    """

    metrics = cve.get(
        "metrics",
        {}
    )

    prioridades = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]

    for versao in prioridades:

        metricas = metrics.get(
            versao
        )

        if not metricas:

            continue

        metric = None

        # -------------------------------------------------
        # Prioriza Primary
        # -------------------------------------------------

        for item in metricas:

            if item.get(
                "type"
            ) == "Primary":

                metric = item

                break

        if metric is None:

            metric = metricas[0]

        dados = metric.get(
            "cvssData",
            {}
        )

        score = dados.get(
            "baseScore",
            0.0
        )

        severidade = dados.get(
            "baseSeverity",
            "UNKNOWN"
        )

        if versao == "cvssMetricV2":

            severidade = metric.get(
                "baseSeverity",
                severidade
            )

        return score, severidade

    return 0.0, "UNKNOWN"


# =========================================================
# EXTRAIR CPE MATCHES
# =========================================================

def extrair_cpe_matches(
    cve
):
    """
    Percorre a estrutura configurations da NVD
    e retorna todos os CPE Matches encontrados.
    """

    matches = []

    configurations = cve.get(
        "configurations",
        []
    )

    def percorrer_no(
        no
    ):

        for match in no.get(
            "cpeMatch",
            []
        ):

            criteria = match.get(
                "criteria"
            )

            if not criteria:

                continue

            matches.append({

                "criteria":
                    criteria,

                "vulnerable":
                    match.get(
                        "vulnerable",
                        True
                    ),

                "versionStartIncluding":
                    match.get(
                        "versionStartIncluding"
                    ),

                "versionStartExcluding":
                    match.get(
                        "versionStartExcluding"
                    ),

                "versionEndIncluding":
                    match.get(
                        "versionEndIncluding"
                    ),

                "versionEndExcluding":
                    match.get(
                        "versionEndExcluding"
                    )
            })

        for child in no.get(
            "children",
            []
        ):

            percorrer_no(
                child
            )

    for configuration in configurations:

        for node in configuration.get(
            "nodes",
            []
        ):

            percorrer_no(
                node
            )

    return matches


# =========================================================
# EXTRAIR AFFECTED
# =========================================================

def extrair_affected(
    cve
):
    """
    Extrai a estrutura affected da CVE.
    """

    resultado = []

    affected = cve.get(
        "affected",
        []
    )

    for origem in affected:

        source = origem.get(
            "source"
        )

        affected_data = origem.get(
            "affectedData",
            []
        )

        for item in affected_data:

            resultado.append({

                "source":
                    source,

                "vendor":
                    item.get(
                        "vendor",
                        ""
                    ),

                "product":
                    item.get(
                        "product",
                        ""
                    ),

                "defaultStatus":
                    item.get(
                        "defaultStatus"
                    ),

                "versions":
                    item.get(
                        "versions",
                        []
                    )
            })

    return resultado


# =========================================================
# NORMALIZAR TEXTO
# =========================================================

def normalizar_texto(
    valor
):
    """
    Normaliza texto para comparação.
    """

    return (
        str(
            valor or ""
        )
        .strip()
        .lower()
        .replace(
            "_",
            " "
        )
        .replace(
            "-",
            " "
        )
        .replace(
            ".",
            " "
        )
    )


def normalizar_token(
    valor
):
    """
    Remove separadores para comparação.
    """

    return (
        normalizar_texto(
            valor
        )
        .replace(
            " ",
            ""
        )
    )


# =========================================================
# COMPONENTES CPE
# =========================================================

def extrair_componentes_cpe(
    cpe
):
    """
    Extrai os principais componentes de um CPE 2.3.
    """

    if not cpe:

        return None

    partes = str(
        cpe
    ).split(
        ":"
    )

    if len(partes) < 6:

        return None

    if (
        partes[0] != "cpe"
        or
        partes[1] != "2.3"
    ):

        return None

    return {

        "part":
            partes[2],

        "vendor":
            partes[3],

        "product":
            partes[4],

        "version":
            partes[5],

        "update":
            partes[6]
            if len(partes) > 6
            else "*",

        "edition":
            partes[10]
            if len(partes) > 10
            else "*",

        "language":
            partes[11]
            if len(partes) > 11
            else "*"
    }


# =========================================================
# TOKENIZAR VERSÃO
# =========================================================

def tokenizar_versao(
    versao
):
    """
    Divide uma versão/build em componentes
    numéricos ou textuais.
    """

    texto = str(
        versao or ""
    ).strip().lower()

    if not texto:

        return []

    partes = re.findall(
        r"\d+|[a-z]+",
        texto
    )

    resultado = []

    for parte in partes:

        if parte.isdigit():

            resultado.append(
                (
                    0,
                    int(parte)
                )
            )

        else:

            resultado.append(
                (
                    1,
                    parte
                )
            )

    return resultado


# =========================================================
# COMPARAR VERSÕES
# =========================================================

def comparar_versoes(
    esquerda,
    direita
):
    """
    Retorna:

        -1 -> esquerda < direita
         0 -> iguais
         1 -> esquerda > direita
    """

    a = tokenizar_versao(
        esquerda
    )

    b = tokenizar_versao(
        direita
    )

    tamanho = max(
        len(a),
        len(b)
    )

    while len(a) < tamanho:

        a.append(
            (
                0,
                0
            )
        )

    while len(b) < tamanho:

        b.append(
            (
                0,
                0
            )
        )

    if a < b:

        return -1

    if a > b:

        return 1

    return 0


# =========================================================
# NORMALIZAR BUILD
# =========================================================

def normalizar_build(
    build
):
    """
    Converte builds da forma:

        10.0.26200.6899

    para:

        26200.6899
    """

    texto = str(
        build or ""
    ).strip()

    if not texto:

        return ""

    if texto.startswith(
        "10.0."
    ):

        texto = texto[
            5:
        ]

    texto = texto.split(
        " "
    )[0]

    return texto


# =========================================================
# COMPARAR BUILDS
# =========================================================

def comparar_builds(
    build_ativo,
    build_nvd
):
    """
    Compara a build instalada com uma
    build/versão da NVD.
    """

    ativo = normalizar_build(
        build_ativo
    )

    nvd = normalizar_build(
        build_nvd
    )

    return comparar_versoes(
        ativo,
        nvd
    )


# =========================================================
# BUILD COMPATÍVEL
# =========================================================

def build_compativel(
    ativo,
    match
):
    """
    Verifica os limites de versão/build
    definidos pelo CPE Match da NVD.
    """

    build_ativo = getattr(
        ativo,
        "build",
        None
    )

    # -----------------------------------------------------
    # Sem build cadastrada
    # -----------------------------------------------------

    if not build_ativo:

        return True

    inicio_incluindo = match.get(
        "versionStartIncluding"
    )

    inicio_excluindo = match.get(
        "versionStartExcluding"
    )

    fim_incluindo = match.get(
        "versionEndIncluding"
    )

    fim_excluindo = match.get(
        "versionEndExcluding"
    )

    # -----------------------------------------------------
    # Limite inferior incluindo
    # -----------------------------------------------------

    if inicio_incluindo:

        if comparar_builds(
            build_ativo,
            inicio_incluindo
        ) < 0:

            return False

    # -----------------------------------------------------
    # Limite inferior excluindo
    # -----------------------------------------------------

    if inicio_excluindo:

        if comparar_builds(
            build_ativo,
            inicio_excluindo
        ) <= 0:

            return False

    # -----------------------------------------------------
    # Limite superior incluindo
    # -----------------------------------------------------

    if fim_incluindo:

        if comparar_builds(
            build_ativo,
            fim_incluindo
        ) > 0:

            return False

    # -----------------------------------------------------
    # Limite superior excluindo
    # -----------------------------------------------------

    if fim_excluindo:

        if comparar_builds(
            build_ativo,
            fim_excluindo
        ) >= 0:

            return False

    return True


# =========================================================
# CPE COMPATÍVEL
# =========================================================

def cpe_match_compativel(
    cpe_ativo,
    match
):
    """
    Compara o CPE do ativo com o criteria
    armazenado pela NVD.
    """

    componentes_ativo = (
        extrair_componentes_cpe(
            cpe_ativo
        )
    )

    componentes_nvd = (
        extrair_componentes_cpe(
            match.get(
                "criteria",
                ""
            )
        )
    )

    if (
        not componentes_ativo
        or
        not componentes_nvd
    ):

        return False

    # =====================================================
    # PART
    # =====================================================

    if (
        componentes_nvd["part"] != "*"
        and
        componentes_ativo["part"]
        !=
        componentes_nvd["part"]
    ):

        return False

    # =====================================================
    # VENDOR
    # =====================================================

    vendor_ativo = normalizar_token(
        componentes_ativo["vendor"]
    )

    vendor_nvd = normalizar_token(
        componentes_nvd["vendor"]
    )

    if (
        vendor_nvd != "*"
        and
        vendor_ativo != vendor_nvd
    ):

        return False

    # =====================================================
    # PRODUTO
    # =====================================================

    produto_ativo = normalizar_token(
        componentes_ativo["product"]
    )

    produto_nvd = normalizar_token(
        componentes_nvd["product"]
    )

    if (
        produto_nvd != "*"
        and
        produto_ativo != produto_nvd
    ):

        return False

    # =====================================================
    # VERSÃO DO CPE
    # =====================================================

    versao_ativo = componentes_ativo[
        "version"
    ]

    versao_nvd = componentes_nvd[
        "version"
    ]

    if versao_nvd not in (
        "*",
        "-"
    ):

        if normalizar_token(
            versao_ativo
        ) != normalizar_token(
            versao_nvd
        ):

            return False

    # =====================================================
    # BUILD
    # =====================================================

    if not build_compativel(
        # O objeto match contém somente os critérios.
        # A build vem do ativo.
        # O ativo será inserido pelo chamador quando
        # necessário.
        #
        # Como esta função não recebe o ativo diretamente,
        # a validação de build será feita em
        # ativo_e_afetado().
        None,
        {}
    ):

        pass

    return True


# =========================================================
# CPE COMPATÍVEL COM ATIVO
# =========================================================

def cpe_match_compativel_ativo(
    ativo,
    match
):
    """
    Versão completa da comparação de CPE,
    incluindo build.
    """

    cpe_ativo = getattr(
        ativo,
        "cpe",
        None
    )

    if not cpe_ativo:

        return False

    componentes_ativo = (
        extrair_componentes_cpe(
            cpe_ativo
        )
    )

    componentes_nvd = (
        extrair_componentes_cpe(
            match.get(
                "criteria",
                ""
            )
        )
    )

    if (
        not componentes_ativo
        or
        not componentes_nvd
    ):

        return False

    # -----------------------------------------------------
    # PART
    # -----------------------------------------------------

    if (
        componentes_nvd["part"] != "*"
        and
        componentes_ativo["part"]
        !=
        componentes_nvd["part"]
    ):

        return False

    # -----------------------------------------------------
    # VENDOR
    # -----------------------------------------------------

    vendor_ativo = normalizar_token(
        componentes_ativo["vendor"]
    )

    vendor_nvd = normalizar_token(
        componentes_nvd["vendor"]
    )

    if (
        vendor_nvd != "*"
        and
        vendor_ativo != vendor_nvd
    ):

        return False

    # -----------------------------------------------------
    # PRODUTO
    # -----------------------------------------------------

    produto_ativo = normalizar_token(
        componentes_ativo["product"]
    )

    produto_nvd = normalizar_token(
        componentes_nvd["product"]
    )

    if (
        produto_nvd != "*"
        and
        produto_ativo != produto_nvd
    ):

        return False

    # -----------------------------------------------------
    # VERSÃO
    # -----------------------------------------------------

    versao_nvd = componentes_nvd[
        "version"
    ]

    versao_ativo = componentes_ativo[
        "version"
    ]

    if versao_nvd not in (
        "*",
        "-"
    ):

        if normalizar_token(
            versao_ativo
        ) != normalizar_token(
            versao_nvd
        ):

            return False

    # -----------------------------------------------------
    # BUILD
    # -----------------------------------------------------

    if not build_compativel(
        ativo,
        match
    ):

        return False

    return True


# =========================================================
# AFFECTED COMPATÍVEL
# =========================================================

def affected_compativel(
    ativo: Ativo,
    affected
):
    """
    Faz fallback usando a estrutura affected
    quando o CPE não for suficiente.
    """

    produto_ativo = normalizar_texto(
        getattr(
            ativo,
            "produto",
            ""
        )
    )

    versao_ativo = str(
        getattr(
            ativo,
            "versao",
            ""
        )
        or ""
    ).strip()

    vendor = normalizar_texto(
        affected.get(
            "vendor",
            ""
        )
    )

    product = normalizar_texto(
        affected.get(
            "product",
            ""
        )
    )

    produto_nvd = (
        f"{vendor} {product}"
    ).strip()

    if not produto_nvd:

        return False

    # =====================================================
    # WINDOWS 11
    # =====================================================

    if "windows 11" in produto_ativo:

        if "windows 11" not in produto_nvd:

            return False

        if versao_ativo.lower() in (
            "",
            "11",
            "windows 11",
            "25h2",
            "24h2"
        ):

            return True

        texto_nvd = normalizar_token(
            produto_nvd
        )

        versao_normalizada = normalizar_token(
            versao_ativo
        )

        if versao_normalizada in texto_nvd:

            return True

        versoes = affected.get(
            "versions",
            []
        )

        for versao_info in versoes:

            if versao_affected_compativel(
                versao_ativo,
                versao_info
            ):

                return True

        return False

    # =====================================================
    # WINDOWS 10
    # =====================================================

    if "windows 10" in produto_ativo:

        if "windows 10" not in produto_nvd:

            return False

        if versao_ativo.lower() in (
            "",
            "10",
            "windows 10"
        ):

            return True

        texto_nvd = normalizar_token(
            produto_nvd
        )

        if normalizar_token(
            versao_ativo
        ) in texto_nvd:

            return True

        for versao_info in affected.get(
            "versions",
            []
        ):

            if versao_affected_compativel(
                versao_ativo,
                versao_info
            ):

                return True

        return False

    # =====================================================
    # KALI
    # =====================================================

    if "kali" in produto_ativo:

        return (
            "kali" in produto_nvd
            or
            "debian" in produto_nvd
            or
            "linux" in produto_nvd
        )

    # =====================================================
    # DEBIAN
    # =====================================================

    if "debian" in produto_ativo:

        return (
            "debian" in produto_nvd
            or
            "linux" in produto_nvd
        )

    # =====================================================
    # UBUNTU
    # =====================================================

    if "ubuntu" in produto_ativo:

        return (
            "ubuntu"
            in
            produto_nvd
        )

    # =====================================================
    # MACOS
    # =====================================================

    if (
        "macos" in produto_ativo
        or
        "mac os" in produto_ativo
    ):

        return (
            "macos" in produto_nvd
            or
            "mac os" in produto_nvd
            or
            "apple" in produto_nvd
        )

    # =====================================================
    # APACHE
    # =====================================================

    if "apache" in produto_ativo:

        return (
            "apache"
            in
            produto_nvd
        )

    # =====================================================
    # NGINX
    # =====================================================

    if "nginx" in produto_ativo:

        return (
            "nginx"
            in
            produto_nvd
        )

    # =====================================================
    # OPENSSL
    # =====================================================

    if "openssl" in produto_ativo:

        return (
            "openssl"
            in
            produto_nvd
        )

    # =====================================================
    # GENÉRICO
    # =====================================================

    produto_ativo_token = normalizar_token(
        produto_ativo
    )

    produto_nvd_token = normalizar_token(
        produto_nvd
    )

    return (
        produto_ativo_token in produto_nvd_token
        or
        produto_nvd_token in produto_ativo_token
    )


# =========================================================
# VERSÃO AFFECTED
# =========================================================

def versao_affected_compativel(
    versao_ativo,
    versao_info
):
    """
    Verifica uma entrada da estrutura affected.
    """

    if not versao_info:

        return False

    status = str(
        versao_info.get(
            "status",
            ""
        )
    ).lower().strip()

    if status not in (
        "affected",
        "vulnerable"
    ):

        return False

    versao_ativo = str(
        versao_ativo or ""
    ).strip()

    version = str(
        versao_info.get(
            "version",
            ""
        )
    ).strip()

    less_than = versao_info.get(
        "lessThan"
    )

    less_equal = versao_info.get(
        "lessThanOrEqual"
    )

    greater_than = versao_info.get(
        "greaterThan"
    )

    greater_equal = versao_info.get(
        "greaterThanOrEqual"
    )

    # -----------------------------------------------------
    # Versão exata
    # -----------------------------------------------------

    if (
        version
        and
        version != "0"
        and
        not less_than
        and
        not less_equal
        and
        not greater_than
        and
        not greater_equal
    ):

        return (
            normalizar_token(
                versao_ativo
            )
            ==
            normalizar_token(
                version
            )
        )

    # -----------------------------------------------------
    # Limites
    # -----------------------------------------------------

    if greater_than:

        if comparar_versoes(
            versao_ativo,
            greater_than
        ) <= 0:

            return False

    if greater_equal:

        if comparar_versoes(
            versao_ativo,
            greater_equal
        ) < 0:

            return False

    if less_than:

        if comparar_versoes(
            versao_ativo,
            less_than
        ) >= 0:

            return False

    if less_equal:

        if comparar_versoes(
            versao_ativo,
            less_equal
        ) > 0:

            return False

    if (
        less_than
        or
        less_equal
        or
        greater_than
        or
        greater_equal
    ):

        return True

    return False


# =========================================================
# ATIVO É AFETADO
# =========================================================

def ativo_e_afetado(
    ativo: Ativo,
    vulnerabilidade: dict
):
    """
    Faz a correlação do ativo.

    Ordem:

        1. CPE
        2. AFFECTED
        3. False
    """

    cpe_ativo = getattr(
        ativo,
        "cpe",
        None
    )

    cpes = vulnerabilidade.get(
        "cpes",
        []
    )

    # =====================================================
    # CPE
    # =====================================================

    if (
        cpe_ativo
        and
        cpes
    ):

        for match in cpes:

            if isinstance(
                match,
                str
            ):

                match = {
                    "criteria":
                        match,

                    "vulnerable":
                        True
                }

            if match.get(
                "vulnerable"
            ) is False:

                continue

            if cpe_match_compativel_ativo(
                ativo,
                match
            ):

                return True

    # =====================================================
    # AFFECTED
    # =====================================================

    affected = vulnerabilidade.get(
        "affected",
        []
    )

    if affected:

        for item in affected:

            if affected_compativel(
                ativo,
                item
            ):

                return True

    return False


# =========================================================
# CONSULTAR NVD
# =========================================================

def consultar_nvd_periodo(
    inicio,
    fim
):
    """
    Consulta a NVD utilizando intervalo de publicação.
    """

    vulnerabilidades = []

    start_index = 0

    while True:

        parametros = {

            "pubStartDate":
                inicio.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                ),

            "pubEndDate":
                fim.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                ),

            "resultsPerPage":
                RESULTADOS_POR_PAGINA,

            "startIndex":
                start_index
        }

        dados = None

        # =================================================
        # TENTATIVAS
        # =================================================

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

                # -----------------------------------------
                # 429
                # -----------------------------------------

                if resposta.status_code == 429:

                    if (
                        tentativa
                        >=
                        MAX_TENTATIVAS
                    ):

                        resposta.raise_for_status()

                    espera = (
                        15
                        *
                        tentativa
                    )

                    print(
                        "HTTP 429 - "
                        "limite da NVD."
                    )

                    print(
                        f"Aguardando {espera}s..."
                    )

                    time.sleep(
                        espera
                    )

                    continue

                resposta.raise_for_status()

                dados = resposta.json()

                break

            except requests.exceptions.RequestException as erro:

                if (
                    tentativa
                    >=
                    MAX_TENTATIVAS
                ):

                    raise

                espera = (
                    10
                    *
                    tentativa
                )

                print(
                    "Erro ao consultar NVD:",
                    erro
                )

                print(
                    f"Nova tentativa em "
                    f"{espera}s..."
                )

                time.sleep(
                    espera
                )

        if dados is None:

            raise RuntimeError(
                "A NVD não retornou dados."
            )

        total_resultados = dados.get(
            "totalResults",
            0
        )

        candidatos = dados.get(
            "vulnerabilities",
            []
        )

        print()
        print(
            "Consultando NVD..."
        )

        print(
            "Período:",
            inicio,
            "até",
            fim
        )

        print(
            "StartIndex:",
            start_index
        )

        print(
            "Resultados encontrados:",
            total_resultados
        )

        print(
            "Resultados recebidos:",
            len(candidatos)
        )

        # =================================================
        # CVEs
        # =================================================

        for item in candidatos:

            cve = item.get(
                "cve",
                {}
            )

            if not cve:

                continue

            score, severidade = (
                extrair_cvss(
                    cve
                )
            )

            vulnerabilidades.append({

                "id":
                    cve.get(
                        "id",
                        "N/A"
                    ),

                "descricao":
                    extrair_descricao(
                        cve
                    ),

                "cvss":
                    score,

                "severidade":
                    severidade,

                "publicado":
                    formatar_data_nvd(
                        cve.get(
                            "published",
                            ""
                        )
                    ),

                "url":
                    (
                        "https://nvd.nist.gov/vuln/detail/"
                        +
                        cve.get(
                            "id",
                            ""
                        )
                    ),

                "cpes":
                    extrair_cpe_matches(
                        cve
                    ),

                "affected":
                    extrair_affected(
                        cve
                    )
            })

        # =================================================
        # PAGINAÇÃO
        # =================================================

        if not candidatos:

            break

        start_index += len(
            candidatos
        )

        if (
            start_index
            >=
            total_resultados
        ):

            break

        print(
            f"Aguardando "
            f"{INTERVALO_ENTRE_PAGINAS}s..."
        )

        time.sleep(
            INTERVALO_ENTRE_PAGINAS
        )

    return vulnerabilidades


# =========================================================
# BUSCAR CVE EXISTENTE
# =========================================================

def buscar_vulnerabilidade_existente(
    db: Session,
    cve
):

    return (
        db.query(
            Vulnerabilidade
        )
        .filter(
            Vulnerabilidade.cve
            ==
            cve
        )
        .first()
    )


# =========================================================
# SALVAR / ATUALIZAR CVE
# =========================================================

def salvar_cve(
    db: Session,
    dados_cve: dict
):
    """
    Salva nova vulnerabilidade ou atualiza uma já existente.
    """

    existente = (
        buscar_vulnerabilidade_existente(
            db,
            dados_cve["id"]
        )
    )

    cpes_json = json.dumps(
        dados_cve.get(
            "cpes",
            []
        ),
        ensure_ascii=False
    )

    affected_json = json.dumps(
        dados_cve.get(
            "affected",
            []
        ),
        ensure_ascii=False
    )

    # =====================================================
    # EXISTENTE
    # =====================================================

    if existente:

        existente.descricao = (
            dados_cve[
                "descricao"
            ]
        )

        existente.severidade = (
            dados_cve[
                "severidade"
            ]
        )

        existente.cvss = (
            dados_cve[
                "cvss"
            ]
        )

        existente.publicado = (
            dados_cve[
                "publicado"
            ]
        )

        existente.url = (
            dados_cve[
                "url"
            ]
        )

        existente.cpes = (
            cpes_json
        )

        existente.affected = (
            affected_json
        )

        db.flush()

        return existente, False

    # =====================================================
    # NOVA
    # =====================================================

    nova = Vulnerabilidade(

        cve=
            dados_cve[
                "id"
            ],

        descricao=
            dados_cve[
                "descricao"
            ],

        severidade=
            dados_cve[
                "severidade"
            ],

        cvss=
            dados_cve[
                "cvss"
            ],

        publicado=
            dados_cve[
                "publicado"
            ],

        url=
            dados_cve[
                "url"
            ],

        cpes=
            cpes_json,

        affected=
            affected_json
    )

    db.add(
        nova
    )

    db.flush()

    return nova, True


# =========================================================
# MONTAR E-MAIL
# =========================================================

def montar_email_vulnerabilidade(
    ativo: Ativo,
    vulnerabilidade: Vulnerabilidade
):
    """
    Monta o assunto e o corpo do alerta.
    """

    assunto = (
        "[VulnMonitor] Nova vulnerabilidade detectada"
    )

    corpo = f"""
Uma nova vulnerabilidade foi identificada em um ativo monitorado pelo VulnMonitor.

ATIVO
========================================
Nome: {ativo.nome}
Produto: {ativo.produto}
Versão: {ativo.versao}
Build: {getattr(ativo, "build", None) or "Não informada"}
CPE: {getattr(ativo, "cpe", None) or "Não informado"}

VULNERABILIDADE
========================================
CVE: {vulnerabilidade.cve}
Severidade: {vulnerabilidade.severidade or "UNKNOWN"}
CVSS: {
    vulnerabilidade.cvss
    if vulnerabilidade.cvss is not None
    else "Não informado"
}
Publicado: {vulnerabilidade.publicado or "Não informado"}

DESCRIÇÃO
========================================
{vulnerabilidade.descricao or "Sem descrição"}

REFERÊNCIA NVD
========================================
{vulnerabilidade.url or "Não disponível"}

Este alerta foi gerado automaticamente pelo VulnMonitor.
"""

    return assunto, corpo


# =========================================================
# NOTIFICAR RESPONSÁVEL
# =========================================================

def notificar_vulnerabilidade(
    ativo: Ativo,
    vulnerabilidade: Vulnerabilidade,
    relacao: AtivoVulnerabilidade
):
    """
    Envia o alerta e marca notificado = 1
    somente quando o envio for concluído.

    Em caso de erro, mantém notificado = 0.
    """

    email = getattr(
        ativo,
        "email_responsavel",
        None
    )

    if not email:

        print()
        print(
            "ATIVO SEM E-MAIL DE RESPONSÁVEL"
        )

        print(
            "Ativo:",
            ativo.nome
        )

        print(
            "CVE:",
            vulnerabilidade.cve
        )

        return False

    assunto, corpo = (
        montar_email_vulnerabilidade(
            ativo,
            vulnerabilidade
        )
    )

    try:

        enviar_email(
            destinatario=email,
            assunto=assunto,
            corpo=corpo
        )

        relacao.notificado = 1

        print()
        print(
            "========================================"
        )

        print(
            "NOTIFICAÇÃO ENVIADA"
        )

        print(
            "========================================"
        )

        print(
            "Ativo:",
            ativo.nome
        )

        print(
            "CVE:",
            vulnerabilidade.cve
        )

        print(
            "Destinatário:",
            email
        )

        print(
            "notificado = 1"
        )

        print(
            "========================================"
        )

        return True

    except Exception as erro:

        relacao.notificado = 0

        print()
        print(
            "========================================"
        )

        print(
            "ERRO AO ENVIAR NOTIFICAÇÃO"
        )

        print(
            "========================================"
        )

        print(
            "Ativo:",
            ativo.nome
        )

        print(
            "CVE:",
            vulnerabilidade.cve
        )

        print(
            "Destinatário:",
            email
        )

        print(
            "Erro:",
            erro
        )

        print(
            "notificado permanece 0"
        )

        print(
            "========================================"
        )

        return False


# =========================================================
# RELACIONAR ATIVO
# =========================================================

def relacionar_ativo(
    db: Session,
    ativo: Ativo,
    vulnerabilidade: Vulnerabilidade,
    notificar: bool = False
):
    """
    Cria ou recupera o relacionamento.

    Caso notificar=True:

        - nova relação -> envia alerta;
        - relação existente com notificado=0
          -> tenta enviar novamente;
        - relação já notificada -> não envia.
    """

    relacao = (
        db.query(
            AtivoVulnerabilidade
        )
        .filter(
            AtivoVulnerabilidade.ativo_id
            ==
            ativo.id,

            AtivoVulnerabilidade.vulnerabilidade_id
            ==
            vulnerabilidade.id
        )
        .first()
    )

    # =====================================================
    # RELAÇÃO JÁ EXISTE
    # =====================================================

    if relacao:

        # -------------------------------------------------
        # Já foi enviada
        # -------------------------------------------------

        if (
            notificar
            and
            relacao.notificado == 0
        ):

            notificar_vulnerabilidade(
                ativo,
                vulnerabilidade,
                relacao
            )

        return False

    # =====================================================
    # NOVA RELAÇÃO
    # =====================================================

    relacao = AtivoVulnerabilidade(

        ativo_id=
            ativo.id,

        vulnerabilidade_id=
            vulnerabilidade.id,

        notificado=0
    )

    db.add(
        relacao
    )

    db.flush()

    # =====================================================
    # NOTIFICAÇÃO
    # =====================================================

    if notificar:

        notificar_vulnerabilidade(
            ativo,
            vulnerabilidade,
            relacao
        )

    return True


# =========================================================
# VULNERABILIDADE ORM -> DICT
# =========================================================

def vulnerabilidade_para_dict(
    vulnerabilidade:
        Vulnerabilidade
):
    """
    Converte a vulnerabilidade do banco para dict.
    """

    try:

        cpes = json.loads(
            vulnerabilidade.cpes
            or "[]"
        )

    except Exception:

        cpes = []

    try:

        affected = json.loads(
            vulnerabilidade.affected
            or "[]"
        )

    except Exception:

        affected = []

    return {

        "id":
            vulnerabilidade.cve,

        "descricao":
            vulnerabilidade.descricao,

        "severidade":
            vulnerabilidade.severidade,

        "cvss":
            vulnerabilidade.cvss,

        "publicado":
            vulnerabilidade.publicado,

        "url":
            vulnerabilidade.url,

        "cpes":
            cpes,

        "affected":
            affected
    }


# =========================================================
# REPROCESSAR VULNERABILIDADES EXISTENTES
# =========================================================

def relacionar_vulnerabilidades_existentes(
    db: Session,
    ativos
):
    """
    Reprocessa as CVEs existentes no banco.

    IMPORTANTE:

    Esta função NÃO envia e-mails.

    Ela serve para reconstruir relacionamentos.
    """

    vulnerabilidades = (
        db.query(
            Vulnerabilidade
        )
        .all()
    )

    total = 0

    for ativo in ativos:

        existentes = {

            rel.vulnerabilidade_id

            for rel in (
                db.query(
                    AtivoVulnerabilidade
                )
                .filter(
                    AtivoVulnerabilidade.ativo_id
                    ==
                    ativo.id
                )
                .all()
            )
        }

        for vulnerabilidade in vulnerabilidades:

            if (
                vulnerabilidade.id
                in
                existentes
            ):

                continue

            dados = (
                vulnerabilidade_para_dict(
                    vulnerabilidade
                )
            )

            if not ativo_e_afetado(
                ativo,
                dados
            ):

                continue

            db.add(
                AtivoVulnerabilidade(

                    ativo_id=
                        ativo.id,

                    vulnerabilidade_id=
                        vulnerabilidade.id,

                    notificado=0
                )
            )

            total += 1

            print(
                "RELACIONAMENTO HISTÓRICO:",
                ativo.nome,
                "->",
                vulnerabilidade.cve
            )

    return total


# =========================================================
# EXECUTAR ATUALIZAÇÃO
# =========================================================

def executar_atualizacao(
    db: Session
):
    """
    Executa a atualização incremental completa.

    Fluxo:

        1. Define período
        2. Consulta NVD
        3. Salva/atualiza CVEs
        4. Verifica ativos
        5. Cria relacionamentos
        6. Envia alertas para novas relações
        7. Reprocessa relações históricas
        8. Registra resultado
    """

    inicio, fim = (
        definir_periodo_atualizacao(
            db
        )
    )

    atualizacao = Atualizacao(

        iniciada_em=
            datetime.utcnow(),

        status=
            "EM_ANDAMENTO",

        quantidade_cves=
            0
    )

    db.add(
        atualizacao
    )

    db.commit()

    try:

        print()
        print(
            "========================================"
        )

        print(
            "INICIANDO ATUALIZAÇÃO NVD"
        )

        print(
            "========================================"
        )

        print(
            "Início:",
            inicio
        )

        print(
            "Fim:",
            fim
        )

        # =================================================
        # CONSULTA
        # =================================================

        vulnerabilidades = (
            consultar_nvd_periodo(
                inicio,
                fim
            )
        )

        print()
        print(
            "CVEs recebidas:",
            len(
                vulnerabilidades
            )
        )

        # =================================================
        # ATIVOS
        # =================================================

        ativos = (
            db.query(
                Ativo
            )
            .all()
        )

        print(
            "Ativos cadastrados:",
            len(
                ativos
            )
        )

        novas_cves = 0

        novos_relacionamentos = 0

        notificacoes_enviadas = 0

        # =================================================
        # PROCESSAMENTO
        # =================================================

        for dados_cve in vulnerabilidades:

            vulnerabilidade, nova = (
                salvar_cve(
                    db,
                    dados_cve
                )
            )

            if nova:

                novas_cves += 1

            # -------------------------------------------------
            # RELACIONAR COM ATIVOS
            # -------------------------------------------------

            for ativo in ativos:

                if not ativo_e_afetado(
                    ativo,
                    dados_cve
                ):

                    continue

                antes = (
                    db.query(
                        AtivoVulnerabilidade
                    )
                    .filter(
                        AtivoVulnerabilidade.ativo_id
                        ==
                        ativo.id,

                        AtivoVulnerabilidade.vulnerabilidade_id
                        ==
                        vulnerabilidade.id
                    )
                    .first()
                )

                criada = relacionar_ativo(

                    db,

                    ativo,

                    vulnerabilidade,

                    notificar=True
                )

                if criada:

                    novos_relacionamentos += 1

                    print()
                    print(
                        "RELACIONAMENTO:",
                        ativo.nome,
                        "->",
                        vulnerabilidade.cve
                    )

                depois = (
                    db.query(
                        AtivoVulnerabilidade
                    )
                    .filter(
                        AtivoVulnerabilidade.ativo_id
                        ==
                        ativo.id,

                        AtivoVulnerabilidade.vulnerabilidade_id
                        ==
                        vulnerabilidade.id
                    )
                    .first()
                )

                # -------------------------------------------------
                # Conta envio realizado
                # -------------------------------------------------

                if (
                    depois
                    and
                    depois.notificado == 1
                    and
                    (
                        antes is None
                        or
                        antes.notificado == 0
                    )
                ):

                    notificacoes_enviadas += 1

        # =================================================
        # RELAÇÕES HISTÓRICAS
        # =================================================

        historicos = (
            relacionar_vulnerabilidades_existentes(
                db,
                ativos
            )
        )

        novos_relacionamentos += (
            historicos
        )

        # =================================================
        # FINALIZA
        # =================================================

        atualizacao.finalizada_em = (
            datetime.utcnow()
        )

        atualizacao.status = (
            "CONCLUIDA"
        )

        atualizacao.quantidade_cves = (
            novas_cves
        )

        atualizacao.erro = None

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
            "CVEs recebidas:",
            len(
                vulnerabilidades
            )
        )

        print(
            "CVEs novas:",
            novas_cves
        )

        print(
            "Novos relacionamentos:",
            novos_relacionamentos
        )

        print(
            "Notificações enviadas:",
            notificacoes_enviadas
        )

        print(
            "========================================"
        )

        return {

            "status":
                "CONCLUIDA",

            "cves_recebidas":
                len(
                    vulnerabilidades
                ),

            "cves_novas":
                novas_cves,

            "relacionamentos_novos":
                novos_relacionamentos,

            "notificacoes_enviadas":
                notificacoes_enviadas
        }

    except Exception as erro:

        db.rollback()

        atualizacao.status = (
            "ERRO"
        )

        atualizacao.finalizada_em = (
            datetime.utcnow()
        )

        atualizacao.erro = str(
            erro
        )

        db.add(
            atualizacao
        )

        db.commit()

        print()
        print(
            "========================================"
        )

        print(
            "ERRO NA ATUALIZAÇÃO"
        )

        print(
            "========================================"
        )

        print(
            erro
        )

        print(
            "========================================"
        )

        raise