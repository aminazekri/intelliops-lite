import re

from src.contrat import Evenement, SEVERITES

_SECRET = re.compile(r"(password|passwd|token|secret|api_key)(\s*[=:]\s*)([^\s,;]+)",
                     re.IGNORECASE)


def masquer_secrets(texte: str) -> str:
    return _SECRET.sub(lambda m: m.group(1) + m.group(2) + "[SECRET]", texte)


def normaliser_docker(ligne: str, numero: int,
                      environment: str = "production") -> Evenement:
    raise NotImplementedError


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