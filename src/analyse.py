import re
from src.contrat import Analyse, Evenement


def est_doublon(evt: Evenement, deja_vus: set) -> bool:
    cle = (evt.source, evt.component, evt.event_type, evt.message)
    if cle in deja_vus:
        return True
    deja_vus.add(cle)
    return False

def rechercher_runbook(evt: Evenement, base: dict):
    message = evt.message.lower()
    for mot_cle, procedure in base.items():
        if mot_cle.lower() in message:
            return procedure
    return None

def classer(evt: Evenement) -> str:
    if evt.event_type == "CONTAINER_RESTART":
        correspondance = re.search(r"restarts=(\d+)", evt.message)
        restarts = int(correspondance.group(1)) if correspondance else 0
        return "CRITICAL" if restarts >= 10 else "MEDIUM"
    if evt.event_type == "VULNERABILITY" and evt.severity == "CRITICAL":
        return "HIGH"
    return evt.severity


def analyser(evt: Evenement, base: dict) -> Analyse:
    raise NotImplementedError