from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os
from groq import Groq
from dotenv import load_dotenv
from datetime import datetime

# Charger les variables d'environnement (.env)
load_dotenv()

# Créer l'application FastAPI
app = FastAPI(title="ORCHESTRA")

# Servir les fichiers CSS et JS
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configurer les templates HTML
templates = Jinja2Templates(directory="templates")

# Connecter Groq
client = Groq(api_key=os.getenv("GROQ_API_KEY"))


# ── Route 1 : Afficher l'interface web ─────────
@app.get("/", response_class=HTMLResponse)
async def interface(request: Request):
    return templates.TemplateResponse(request, "index.html")


# ── Route 2 : Vérifier que le serveur tourne ───
@app.get("/health")
def health():
    return {"statut": "ok"}


# ── Route 3 : Analyser une cible avec Groq ─────
@app.get("/analyser")
def analyser(cible: str):

    # Données de démonstration
    # (sera remplacé par Nikto plus tard)
    findings = [
        {
            "id": "finding_1",
            "titre": "SQL Injection potentielle",
            "severite": "high",
            "description": "Paramètre non validé détecté dans l'URL"
        },
        {
            "id": "finding_2",
            "titre": "HTTP sans HTTPS",
            "severite": "medium",
            "description": "Le site ne redirige pas vers HTTPS"
        },
        {
            "id": "finding_3",
            "titre": "Headers manquants",
            "severite": "low",
            "description": "X-Frame-Options et CSP absents"
        }
    ]

    # Envoyer à Groq pour analyse
    prompt = f"""
Tu es un expert en cybersécurité.
Voici les résultats d'une analyse sur {cible} :

{str(findings)}

Produis une synthèse claire en français avec :
1. Résumé des risques
2. Les problèmes les plus critiques
3. Recommandations concrètes
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )

    synthese = response.choices[0].message.content

    # Retourner le rapport complet
    return {
        "cible": cible,
        "timestamp": datetime.now().isoformat(),
        "findings": findings,
        "synthese": synthese,
        "statut": "success"
    }