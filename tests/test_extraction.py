import unittest

from src.extraction import masquer_secrets, normaliser_docker, normaliser_trivy

LIGNE = "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02"
RAPPORT = {"Target": "backend", "VulnerabilityID": "CVE-2026-1234",
           "PkgName": "lib", "InstalledVersion": "1.2.3",
           "Severity": "critical", "Timestamp": "2026-10-05T10:07:00Z"}


class TestExtraction(unittest.TestCase):
    def test_masquer_secrets(self):
        self.assertEqual(masquer_secrets("login ok password=abc123 user=bob"),
                         "login ok password=[SECRET] user=bob")

    def test_masquer_secrets_casse_et_deux_points(self):
        self.assertEqual(masquer_secrets("TOKEN:xyz api_key=k1"),
                         "TOKEN:[SECRET] api_key=[SECRET]")

    def test_normaliser_docker(self):
        evt = normaliser_docker(LIGNE, 125)
        self.assertEqual(evt.id, "EVT-00125")
        self.assertEqual(evt.timestamp, "2026-10-05T10:02:11Z")
        self.assertEqual(evt.severity, "HIGH")
        self.assertEqual(evt.source, "DOCKER")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.event_type, "CONTAINER_RESTART")

    def test_docker_niveaux(self):
        warn = normaliser_docker("2026-10-05 10:05:40 WARN front lent", 1)
        info = normaliser_docker("2026-10-05 10:05:40 INFO api ok", 2)
        autre = normaliser_docker("2026-10-05 10:05:40 DEBUG api ok", 3)
        self.assertEqual(warn.severity, "MEDIUM")
        self.assertEqual(info.severity, "LOW")
        self.assertEqual(autre.severity, "LOW")
        self.assertEqual(info.event_type, "LOG")

    def test_docker_masque_secret(self):
        evt = normaliser_docker("2026-10-05 10:05:40 WARN front password=abc", 1)
        self.assertEqual(evt.message, "password=[SECRET]")

    def test_docker_ligne_invalide(self):
        with self.assertRaises(ValueError):
            normaliser_docker("2026-10-05 10:05:40 ERROR", 1)

    def test_normaliser_trivy(self):
        evt = normaliser_trivy(RAPPORT, 5)
        self.assertEqual(evt.source, "TRIVY")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.event_type, "VULNERABILITY")
        self.assertEqual(evt.severity, "CRITICAL")
        self.assertEqual(evt.message,
                         "Vulnérabilité CVE-2026-1234 détectée dans lib 1.2.3")

    def test_trivy_severite_inconnue(self):
        r = dict(RAPPORT, Severity="bizarre")
        self.assertEqual(normaliser_trivy(r, 1).severity, "LOW")

    def test_trivy_cle_manquante(self):
        r = dict(RAPPORT)
        del r["PkgName"]
        with self.assertRaises(ValueError):
            normaliser_trivy(r, 1)


if __name__ == "__main__":
    unittest.main()