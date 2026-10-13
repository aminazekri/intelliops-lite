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
    raise NotImplementedError