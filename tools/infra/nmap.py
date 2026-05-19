import docker
from tools.base import BaseTool

class NmapTool(BaseTool):
    name        = "nmap"
    category    = "infra"
    description = "Scanner de ports et services — détecte ports ouverts, versions et OS"

    def run(self, cible: str):
        print(f"[NMAP] Lancement sur {cible}...")
        try:
            client = docker.from_env()
            container = client.containers.get("orchestra_nmap")
            result = container.exec_run(
                f"nmap -sV -T4 --top-ports 100 {cible}"
            )
            output = result.output.decode("utf-8")
            print(f"[NMAP] Terminé — {len(output)} caractères")
            return output
        except Exception as e:
            print(f"[NMAP] Erreur : {e}")
            return f"Erreur Nmap : {str(e)}"

    def normalize(self, raw_output):
        findings = []
        for i, ligne in enumerate(raw_output.splitlines()):
            # Lignes contenant des ports ouverts
            if "/tcp" in ligne and "open" in ligne:
                severite = "low"
                if any(m in ligne.lower() for m in ["21", "23", "3389", "445"]):
                    severite = "high"   # FTP, Telnet, RDP, SMB
                elif any(m in ligne.lower() for m in ["80", "8080", "8443"]):
                    severite = "medium"  # HTTP non sécurisé

                findings.append({
                    "id":             f"nmap_{i}",
                    "outil":          self.name,
                    "titre":          f"Port ouvert : {ligne.strip()[:50]}",
                    "severite":       severite,
                    "description":    ligne.strip(),
                    "recommandation": "Vérifier si ce port doit être exposé publiquement"
                })
        return findings