import unittest

from src.analyse import analyser, classer, est_doublon, rechercher_runbook
from src.contrat import RUNBOOKS, Evenement


def evt(event_type="LOG", severity="LOW", message="ok", component="backend"):
    return Evenement("EVT-00001", "2026-10-05T10:00:00Z", "DOCKER", component,
                     "production", event_type, severity, message)


class TestAnalyse(unittest.TestCase):
    def test_doublon(self):
        vus = set()
        self.assertFalse(est_doublon(evt(message="a"), vus))
        self.assertTrue(est_doublon(evt(message="a"), vus))

    def test_doublon_message_different(self):
        vus = set()
        self.assertFalse(est_doublon(evt(message="a"), vus))
        self.assertFalse(est_doublon(evt(message="b"), vus))

    def test_runbook_trouve(self):
        e = evt(message="Conteneur oomkilled sur db-02")
        self.assertEqual(rechercher_runbook(e, RUNBOOKS), RUNBOOKS["OOMKilled"])

    def test_runbook_premier_mot_cle(self):
        e = evt(message="timeout apres OOMKilled")
        self.assertEqual(rechercher_runbook(e, RUNBOOKS), RUNBOOKS["OOMKilled"])

    def test_runbook_absent(self):
        self.assertIsNone(rechercher_runbook(evt(message="tout va bien"), RUNBOOKS))

    def test_classer_redemarrages(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        self.assertEqual(classer(e), "CRITICAL")


    def test_classer_redemarrages_seuil(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=10")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_redemarrages_faibles(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=9")
        self.assertEqual(classer(e), "MEDIUM")

    def test_classer_vulnerabilite_critique(self):
        self.assertEqual(classer(evt("VULNERABILITY", "CRITICAL")), "HIGH")

    def test_classer_vulnerabilite_moyenne(self):
        self.assertEqual(classer(evt("VULNERABILITY", "MEDIUM")), "MEDIUM")

    def test_classer_log(self):
        self.assertEqual(classer(evt("LOG", "MEDIUM")), "MEDIUM")

    def test_analyser_redemarrage(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        a = analyser(e, RUNBOOKS)
        self.assertEqual(a.criticite, "CRITICAL")
        self.assertEqual(a.cause_probable, RUNBOOKS["OOMKilled"])
        self.assertEqual(a.action_recommandee, "Redémarrer backend")
        self.assertTrue(a.sensible)
        self.assertEqual(a.sources, ["DOCKER"])
        self.assertEqual(a.event_id, "EVT-00001")
        self.assertEqual(e.status, "ANALYSED")

    def test_analyser_vulnerabilite(self):
        a = analyser(evt("VULNERABILITY", "CRITICAL", "Vulnérabilité CVE-1"), RUNBOOKS)
        self.assertEqual(a.action_recommandee, "Mettre à jour la dépendance")
        self.assertEqual(a.criticite, "HIGH")
        self.assertTrue(a.sensible)

    def test_analyser_log_simple(self):
        a = analyser(evt("LOG", "LOW", "health check ok"), RUNBOOKS)
        self.assertEqual(a.cause_probable,
                         "Cause inconnue : analyse manuelle requise")
        self.assertEqual(a.action_recommandee, "Consulter les logs")
        self.assertFalse(a.sensible)


if __name__ == "__main__":
    unittest.main()