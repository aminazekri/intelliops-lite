import re

from src.contrat import Evenement, SEVERITES

_SECRET = re.compile(r"(password|passwd|token|secret|api_key)(\s*[=:]\s*)([^\s,;]+)",
                     re.IGNORECASE)


def masquer_secrets(texte: str) -> str:
    return _SECRET.sub(lambda m: m.group(1) + m.group(2) + "[SECRET]", texte)


def normaliser_docker(ligne: str, numero: int,
                      environment: str = "production") -> Evenement:
    champs = ligne.split(maxsplit=4)
    if len(champs) < 5:
        raise ValueError(f"ligne Docker invalide : {ligne!r}")
    date, heure, niveau, composant, message = champs
    message = masquer_secrets(message)
    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=f"{date}T{heure}Z",
        source="DOCKER",
        component=composant,
        environment=environment,
        event_type="CONTAINER_RESTART" if "restarts=" in message else "LOG",
        severity={"ERROR": "HIGH", "WARN": "MEDIUM", "INFO": "LOW"}.get(niveau, "LOW"),
        message=message,
    )


def normaliser_trivy(rapport: dict, numero: int,
                     environment: str = "production") -> Evenement:
    for cle in ("Target", "VulnerabilityID", "PkgName", "InstalledVersion",
                "Severity", "Timestamp"):
        if cle not in rapport:
            raise ValueError(f"clé manquante : {cle}")
    severite = rapport["Severity"].upper()
    if severite not in SEVERITES:
        severite = "LOW"
    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=rapport["Timestamp"],
        source="TRIVY",
        component=rapport["Target"],
        environment=environment,
        event_type="VULNERABILITY",
        severity=severite,
        message=f"Vulnérabilité {rapport['VulnerabilityID']} détectée dans "
                f"{rapport['PkgName']} {rapport['InstalledVersion']}",
    )
