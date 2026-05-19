from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os, subprocess, time
import requests
from groq import Groq
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = FastAPI(title="ORCHESTRA")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
ZAP_URL = os.getenv("ZAP_URL", "http://zap:8080")
ZAP_PASSIVE_ONLY = os.getenv("ZAP_PASSIVE_ONLY", "false").strip().lower() in ["1", "true", "yes"]


# AGENT 1 — ORCHESTRATEUR
# Rôle : analyser la cible et décider quels outils lancer

def agent_orchestrateur(cible: str) -> dict:
    """
    Agent IA qui analyse la cible et décide automatiquement
    quels outils de sécurité utiliser.
    Retourne : { "outils": ["zap", "nikto"], "raison": "..." }
    """
    print(f"[AGENT ORCHESTRATEUR] Analyse de la cible : {cible}")

    prompt = f"""Tu es un agent orchestrateur de sécurité informatique.
On te donne une cible à analyser : {cible}

Ton rôle est de décider quels outils de sécurité utiliser parmi :
- "zap" : scanner dynamique DAST, idéal pour les applications web (URLs HTTP/HTTPS)
- "nikto" : audit de configuration serveur web, idéal pour détecter les headers manquants et mauvaises configs
- "both" : les deux outils combinés, pour une analyse complète

Règles de décision :
- Si la cible est une URL web (commence par http:// ou https://) → utilise "both"
- Si la cible ressemble à une IP ou un domaine simple → utilise "nikto" en priorité
- Si la cible contient un chemin applicatif (/login, /api, etc.) → utilise "zap" en priorité

Réponds UNIQUEMENT en JSON valide, sans texte avant ou après, avec ce format exact :
{{"outils": "both", "raison": "explication courte en français"}}

Les valeurs possibles pour "outils" sont : "zap", "nikto", "both"
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.1  # Réponse déterministe pour l'orchestrateur
        )
        contenu = response.choices[0].message.content.strip()

        # Parser la réponse JSON
        import json
        # Nettoyer si besoin (parfois le LLM ajoute des backticks)
        contenu = contenu.replace("```json", "").replace("```", "").strip()
        decision = json.loads(contenu)

        outils = decision.get("outils", "both")
        raison = decision.get("raison", "Analyse complète recommandée")

        # Validation : s'assurer que la valeur est valide
        if outils not in ["zap", "nikto", "both"]:
            outils = "both"

        print(f"[AGENT ORCHESTRATEUR] Décision : {outils} — {raison}")
        return {"outils": outils, "raison": raison}

    except Exception as e:
        print(f"[AGENT ORCHESTRATEUR] Erreur : {e} — utilisation de 'both' par défaut")
        return {"outils": "both", "raison": "Analyse complète par défaut"}


# AGENT 2 — ANALYSEUR
# Rôle : interpréter les résultats des scans et produire une synthèse
def agent_analyseur(cible: str, output_brut: str, scanners_used: list) -> str:
    """
    Agent IA qui interprète les résultats bruts des outils
    et produit une synthèse claire en français.
    """
    print(f"[AGENT ANALYSEUR] Interprétation des résultats de {', '.join(scanners_used)}...")

    scan_name = ", ".join(scanners_used)

    prompt = f"""Tu es un expert en cybersécurité chargé d'analyser des résultats de scans de sécurité.

Voici les résultats bruts des outils {scan_name} sur la cible : {cible}

--- RÉSULTATS ---
{output_brut[:3500]}
--- FIN RÉSULTATS ---

Produis une synthèse claire et professionnelle en français avec exactement cette structure :

### 1. Résumé des risques principaux
(2-3 phrases résumant l'état général de sécurité de la cible)

### 2. Les 3 problèmes les plus critiques
1. **Problème** : description et impact concret
2. **Problème** : description et impact concret
3. **Problème** : description et impact concret

### 3. Recommandations concrètes
- Recommandation 1
- Recommandation 2
- Recommandation 3
- Recommandation 4

Sois précis, concret et orienté action. Évite le jargon inutile.
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            temperature=0.3
        )
        synthese = response.choices[0].message.content
        print("[AGENT ANALYSEUR] Synthèse produite avec succès.")
        return synthese

    except Exception as e:
        print(f"[AGENT ANALYSEUR] Erreur : {e}")
        return "Erreur lors de la génération de la synthèse IA."


# OUTIL ZAP — Scanner dynamique DAST
def start_zap_scan(cible: str, active_scan: bool = not ZAP_PASSIVE_ONLY):
    if not cible.startswith("http://") and not cible.startswith("https://"):
        cible = "http://" + cible

    session = requests.Session()
    session.headers.update({"Accept": "application/json"})

    # Étape 1 : Attendre que ZAP soit prêt
    print("[ZAP] Attente que ZAP soit prêt...")
    for _ in range(10):
        try:
            session.get(f"{ZAP_URL}/JSON/core/view/version/", timeout=5)
            print("[ZAP] ZAP est prêt !")
            break
        except Exception:
            time.sleep(3)

    # Étape 2 : Accéder à l'URL cible
    print(f"[ZAP] Accès à {cible}...")
    try:
        session.get(
            f"{ZAP_URL}/JSON/core/action/accessUrl/",
            params={"url": cible, "followRedirects": "true"},
            timeout=30
        )
    except Exception as e:
        print(f"[ZAP] AccessUrl warning: {e}")

    # Étape 3 : Spider scan
    print(f"[ZAP] Lancement spider sur {cible}...")
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
            params={"scanId": scan_id},
            timeout=30
        )
        progress = int(status.json().get("status", 0))
        print(f"[ZAP] Spider: {progress}%")
        if progress >= 100:
            break
        time.sleep(2)

    # Étape 4 : Scan passif
    print("[ZAP] Attente du scan passif...")
    for _ in range(15):
        try:
            remaining = session.get(
                f"{ZAP_URL}/JSON/pscan/view/recordsToScan/",
                timeout=10
            )
            records = int(remaining.json().get("recordsToScan", 0))
            print(f"[ZAP] Records restants: {records}")
            if records == 0:
                break
        except Exception:
            pass
        time.sleep(2)

    # Étape 5 : Scan actif
    if active_scan:
        print("[ZAP] Lancement du scan actif...")
        try:
            active = session.post(
                f"{ZAP_URL}/JSON/ascan/action/scan/",
                data={"url": cible, "recurse": "true"},
                timeout=30
            )
            active.raise_for_status()
            active_scan_id = active.json().get("scan")

            while True:
                status = session.get(
                    f"{ZAP_URL}/JSON/ascan/view/status/",
                    params={"scanId": active_scan_id},
                    timeout=30
                )
                progress = int(status.json().get("status", 0))
                print(f"[ZAP] Scan actif: {progress}%")
                if progress >= 100:
                    break
                time.sleep(3)

        except Exception as e:
            print(f"[ZAP] Scan actif ignoré : {e}")
    else:
        print("[ZAP] Mode passif activé : scan actif désactivé.")

    # Étape 6 : Récupérer les alertes
    print("[ZAP] Récupération des alertes...")
    alerts = session.get(
        f"{ZAP_URL}/JSON/core/view/alerts/",
        params={"baseurl": cible, "start": 0, "count": 1000},
        timeout=30
    )
    alerts.raise_for_status()
    alert_list = alerts.json().get("alerts", [])

    if not alert_list:
        # Si aucun résultat avec le filtre baseurl, récupérer toutes les alertes
        print("[ZAP] Aucun alertes pour baseurl, récupération de toutes les alertes...")
        alerts = session.get(
            f"{ZAP_URL}/JSON/core/view/alerts/",
            params={"start": 0, "count": 1000},
            timeout=30
        )
        alerts.raise_for_status()
        alert_list = alerts.json().get("alerts", [])

    print(f"[ZAP] Alertes retournées: {len(alert_list)}")
    return alert_list


def normalize_zap_alerts(alerts):
    findings = []
    for i, alert in enumerate(alerts):
        risk = alert.get("risk", "Low").lower()
        if risk == "high":
            severite = "high"
        elif risk == "medium":
            severite = "medium"
        else:
            severite = "low"

        findings.append({
            "id": f"zap_{i}",
            "outil": "zap",
            "titre": alert.get("name", "Alerte ZAP")[:60],
            "severite": severite,
            "description": alert.get("description", "").strip()[:200],
            "recommandation": alert.get("solution", "").strip()[:200]
        })
    return findings


# OUTIL NIKTO — Audit configuration serveur

def lancer_nikto(cible: str):
    print(f"[NIKTO] Lancement sur {cible}...")
    try:
        resultat = subprocess.run(
            ["docker", "exec", "orchestra_nikto",
             "nikto", "-h", cible, "-maxtime", "60"],
            capture_output=True,
            text=True,
            timeout=90
        )
        output_brut = resultat.stdout
    except Exception as e:
        return [], f"Erreur Nikto : {str(e)}"

    findings = []
    for i, ligne in enumerate(output_brut.splitlines()):
        if "+ " in ligne and len(ligne.strip()) > 5:
            severite = "low"
            if any(m in ligne.lower() for m in ["sql", "injection", "xss"]):
                severite = "high"
            elif any(m in ligne.lower() for m in ["osvdb", "config", "header"]):
                severite = "medium"
            findings.append({
                "id": f"nikto_{i}",
                "outil": "nikto",
                "titre": ligne.strip()[:60],
                "severite": severite,
                "description": ligne.strip(),
                "recommandation": ""
            })
    return findings, output_brut



# ROUTES FASTAPI

@app.get("/", response_class=HTMLResponse)
async def interface(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/health")
def health():
    return {"statut": "ok", "agents": ["orchestrateur", "analyseur"]}


@app.get("/analyser")
def analyser(cible: str):
    """
    Route principale d'analyse.
    1. Agent orchestrateur décide quels outils lancer
    2. Les outils tournent (ZAP et/ou Nikto)
    3. Agent analyseur interprète les résultats
    """

    output_brut = ""
    findings = []
    scanners_used = []

    # ── ÉTAPE 1 : Agent orchestrateur décide ──────────────────────
    decision = agent_orchestrateur(cible)
    scanner = decision["outils"]
    raison_orchestrateur = decision["raison"]
    print(f"[ORCHESTRATEUR] Outils choisis : {scanner}")

    # ── ÉTAPE 2 : Lancement des outils ────────────────────────────

    # Scan ZAP
    if scanner in ["zap", "both"]:
        scanners_used.append("ZAP")
        try:
            alerts = start_zap_scan(cible)
            zap_findings = normalize_zap_alerts(alerts)
            findings.extend(zap_findings)
            zap_output = "\n".join([
                f"{a.get('risk')} - {a.get('name')}: {a.get('url')}"
                for a in alerts
            ])
            output_brut += f"\n=== RÉSULTATS ZAP ===\n{zap_output or 'Aucune alerte détectée.'}"
        except Exception as e:
            output_brut += f"\n=== ERREUR ZAP ===\n{str(e)}"

    # Scan Nikto
    if scanner in ["nikto", "both"]:
        scanners_used.append("Nikto")
        result = lancer_nikto(cible)
        if isinstance(result, tuple):
            nikto_findings, nikto_output = result
            findings.extend(nikto_findings)
            output_brut += f"\n=== RÉSULTATS NIKTO ===\n{nikto_output}"
        else:
            output_brut += "\n=== ERREUR NIKTO ===\nErreur lors du scan Nikto"

    # Si aucun finding
    if not findings:
        findings = [{
            "id": "scan_0",
            "outil": ", ".join(scanners_used),
            "titre": "Scan terminé — aucune vulnérabilité détectée",
            "severite": "low",
            "description": output_brut[:200] if output_brut else "Aucun résultat",
            "recommandation": ""
        }]

    # ── ÉTAPE 3 : Agent analyseur interprète les résultats ─────────
    synthese = agent_analyseur(cible, output_brut, scanners_used)

    # ── ÉTAPE 4 : Retourner le rapport complet ─────────────────────
    return {
        "cible": cible,
        "scanner": scanner,
        "orchestrateur": {
            "outils_choisis": scanner,
            "raison": raison_orchestrateur
        },
        "timestamp": datetime.now().isoformat(),
        "findings": findings,
        "synthese": synthese,
        "statut": "success"
    }
