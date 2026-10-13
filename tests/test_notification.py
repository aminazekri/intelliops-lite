import unittest

from src.contrat import Analyse, Evenement
from src.notification import (choisir_canal, demander_validation, notifier, rediger)


def exemple(sensible=True, criticite="CRITICAL"):
    e = Evenement("EVT-00125", "2026-10-05T10:02:11Z", "DOCKER", "backend",
                  "production", "CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
    a = Analyse("EVT-00125", criticite, "Limite mémoire", "Redémarrer backend",
                sensible, ["DOCKER"])
    return e, a


class TestNotification(unittest.TestCase):
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITICAL"), "TEAMS")
        self.assertEqual(choisir_canal("HIGH"), "TEAMS")
        self.assertEqual(choisir_canal("MEDIUM"), "EMAIL")
        self.assertEqual(choisir_canal("LOW"), "DASHBOARD")

    def test_canal_inconnu(self):
        with self.assertRaises(ValueError):
            choisir_canal("URGENT")

    def test_rediger_cinq_lignes(self):
        e, a = exemple()
        attendu = ("[CRITICAL] Service : backend\n"
                   "Incident : OOMKilled restarts=14\n"
                   "Cause probable : Limite mémoire\n"
                   "Action : Redémarrer backend\n"
                   "Sources : DOCKER")
        self.assertEqual(rediger(e, a), attendu)

    def test_rediger_sources_multiples(self):
        e, a = exemple()
        a.sources = ["DOCKER", "TRIVY"]
        self.assertTrue(rediger(e, a).endswith("Sources : DOCKER, TRIVY"))

    def test_notifier(self):
        e, a = exemple()
        journal = []
        notification = notifier(e, a, journal)
        self.assertEqual(notification.event_id, "EVT-00125")
        self.assertEqual(notification.canal, "TEAMS")
        self.assertEqual(notification.destinataire, "equipe-ops")
        self.assertEqual(len(journal), 1)
        self.assertIs(journal[0], notification)
        self.assertEqual(e.status, "NOTIFIED")

    def test_validation(self):
        _, a = exemple()
        for mot in (" OUI ", "o", "Y", " yes "):
            self.assertTrue(demander_validation(a, mot))
        self.assertFalse(demander_validation(a, "n"))
        self.assertFalse(demander_validation(a, "non"))

    def test_non_sensible_pas_de_validation(self):
        _, a = exemple(sensible=False, criticite="LOW")
        self.assertTrue(demander_validation(a, "non"))


if __name__ == "__main__":
    unittest.main()
