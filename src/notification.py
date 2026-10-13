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
    resultat = Notification(
        event_id=evt.id,
        canal=choisir_canal(analyse.criticite),
        destinataire="equipe-ops",
        message=rediger(evt, analyse),
    )
    journal.append(resultat)
    evt.status = "NOTIFIED"
    return resultat


def demander_validation(analyse: Analyse, reponse: str) -> bool:
    if not analyse.sensible:
        return True
    return "".join(reponse.split()).lower() in ("o", "oui", "y", "yes")
