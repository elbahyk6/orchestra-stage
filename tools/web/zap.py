import time, requests, os
from tools.base import BaseTool

ZAP_URL = os.getenv("ZAP_URL", "http://zap:8080")

class ZapTool(BaseTool):
    name        = "zap"
    category    = "web"
    description = "Scanner dynamique DAST — détecte SQL injection, XSS, CSRF sur applications web"

    def run(self, cible: str):
        if not cible.startswith("http://") and not cible.startswith("https://"):
            cible = "http://" + cible

        session = requests.Session()
        session.headers.update({"Accept": "application/json"})

        # Attendre que ZAP soit prêt
        print("[ZAP] Attente que ZAP soit prêt...")
        for _ in range(10):
            try:
                session.get(f"{ZAP_URL}/JSON/core/view/version/", timeout=5)
                print("[ZAP] ZAP est prêt !")
                break
            except Exception:
                time.sleep(3)

        # Accéder à la cible
        try:
            session.get(
                f"{ZAP_URL}/JSON/core/action/accessUrl/",
                params={"url": cible, "followRedirects": "true"},
                timeout=30
            )
        except Exception as e:
            print(f"[ZAP] AccessUrl warning: {e}")

        # Spider scan
        print(f"[ZAP] Spider sur {cible}...")
        spider = session.get(
            f"{ZAP_URL}/JSON/spider/action/scan/",
            params={"url": cible, "recurse": "true"},
            timeout=30
        )
        spider.raise_for_status()
        scan_id = spider.json().get("scan")

        while True:
            status = session.get(
                f"{ZAP_URL}/JSON/spider/view/status/",
                params={"scanId": scan_id}, timeout=30
            )
            progress = int(status.json().get("status", 0))
            print(f"[ZAP] Spider: {progress}%")
            if progress >= 100:
                break
            time.sleep(2)

        # Scan passif
        print("[ZAP] Scan passif en cours...")
        for _ in range(30):
            try:
                remaining = session.get(
                    f"{ZAP_URL}/JSON/pscan/view/recordsToScan/", timeout=10
                )
                records = int(remaining.json().get("recordsToScan", 0))
                print(f"[ZAP] Records restants: {records}")
                if records == 0:
                    break
            except Exception:
                pass
            time.sleep(3)

        # Scan actif désactivé
        print("[ZAP] Scan actif ignoré — alertes passives uniquement")

        # Récupérer les alertes
        print("[ZAP] Récupération des alertes...")
        alerts = session.get(
            f"{ZAP_URL}/JSON/core/view/alerts/",
            params={"baseurl": cible, "start": 0, "count": 1000}, timeout=30
        )
        alerts.raise_for_status()
        alert_list = alerts.json().get("alerts", [])

        if not alert_list:
            print("[ZAP] Récupération globale...")
            alerts = session.get(
                f"{ZAP_URL}/JSON/core/view/alerts/",
                params={"start": 0, "count": 1000}, timeout=30
            )
            alert_list = alerts.json().get("alerts", [])

        print(f"[ZAP] {len(alert_list)} alertes trouvées")
        return alert_list

    def normalize(self, raw_output):
        findings = []
        for i, alert in enumerate(raw_output):
            risk = alert.get("risk", "Low").lower()
            severite = "high" if risk == "high" else "medium" if risk == "medium" else "low"
            findings.append({
                "id":             f"zap_{i}",
                "outil":          self.name,
                "titre":          alert.get("name", "Alerte ZAP")[:60],
                "severite":       severite,
                "description":    alert.get("description", "").strip()[:200],
                "recommandation": alert.get("solution", "").strip()[:200]
            })
        return findings