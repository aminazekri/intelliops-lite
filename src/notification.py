from src.contrat import Analyse, Evenement, Notification


def choisir_canal(criticite: str) -> str:
    if criticite in ("CRITICAL", "HIGH"):
        return "TEAMS"
    if criticite == "MEDIUM":
        return "EMAIL"
    if criticite == "LOW":
        return "DASHBOARD"
    raise ValueError("Criticité inconnue")


def rediger(evt: Evenement, analyse: Analyse) -> str:
    return "\n".join([
        f"[{analyse.criticite}] Service : {evt.component}",
        f"Incident : {evt.message}",
        f"Cause probable : {analyse.cause_probable}",
        f"Action : {analyse.action_recommandee}",
        f"Sources : {', '.join(analyse.sources)}",
    ])


def notifier(evt: Evenement, analyse: Analyse, journal: list) -> Notification:
    raise NotImplementedError


def demander_validation(analyse: Analyse, reponse: str) -> bool:
    raise NotImplementedError
