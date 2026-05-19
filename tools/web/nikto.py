import docker
from tools.base import BaseTool

class NiktoTool(BaseTool):
    name        = "nikto"
    category    = "web"
    description = "Audit configuration serveur — détecte headers manquants et mauvaises configs"

    def run(self, cible: str):
        print(f"[NIKTO] Lancement sur {cible}...")
        try:
            client = docker.from_env()
            container = client.containers.get("orchestra_nikto")
            result = container.exec_run(
                f"perl /usr/bin/nikto.pl -h {cible} -maxtime 60"
            )
            output = result.output.decode("utf-8")
            print(f"[NIKTO] Terminé — {len(output)} caractères")
            return output
        except Exception as e:
            print(f"[NIKTO] Erreur : {e}")
            return f"Erreur Nikto : {str(e)}"

    def normalize(self, raw_output):
        findings = []
        for i, ligne in enumerate(raw_output.splitlines()):
            if "+ " in ligne and len(ligne.strip()) > 5:
                severite = "low"
                if any(m in ligne.lower() for m in ["sql", "injection", "xss"]):
                    severite = "high"
                elif any(m in ligne.lower() for m in ["osvdb", "config", "header"]):
                    severite = "medium"
                findings.append({
                    "id":             f"nikto_{i}",
                    "outil":          self.name,
                    "titre":          ligne.strip()[:60],
                    "severite":       severite,
                    "description":    ligne.strip(),
                    "recommandation": ""
                })
        return findings