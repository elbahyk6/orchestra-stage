import uuid
import os, json
from fastapi import FastAPI, Request, Cookie, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from typing import Optional
from groq import Groq
from dotenv import load_dotenv
from datetime import datetime
from tools.registry import get_tool, get_all_tools
from database import init_db, sauvegarder_scan, get_historique, get_scan_par_id

load_dotenv()

app = FastAPI(title="ORCHESTRA")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Initialiser la base de données au démarrage
init_db()


# ──────────────────────────────────────────────────────────────
# AGENT 1 — ORCHESTRATEUR
# ──────────────────────────────────────────────────────────────

def agent_orchestrateur(cible: str, type_scan: str = "web") -> dict:
    print(f"[AGENT ORCHESTRATEUR] Cible : {cible} | Type : {type_scan}")

    all_tools = get_all_tools()

    # Filtrer les outils selon le type de scan
    if type_scan == "web":
        outils_filtres = [t for t in all_tools if t["category"] == "web"]
    elif type_scan == "infra":
        outils_filtres = [t for t in all_tools if t["category"] == "infra"]
    elif type_scan == "code":
        outils_filtres = [t for t in all_tools if t["category"] == "code"]
    else:
        outils_filtres = all_tools

    if not outils_filtres:
        outils_filtres = all_tools

    tools_description = "\n".join([
        f"- \"{t['name']}\" : {t['description']}"
        for t in outils_filtres
    ])

    prompt = f"""Tu es un agent orchestrateur de sécurité informatique.
Cible à analyser : {cible}
Type d'analyse demandé : {type_scan}

Outils disponibles pour ce type d'analyse :
{tools_description}

Ton rôle est de choisir le(s) outil(s) les plus adaptés parmi la liste ci-dessus.

Réponds UNIQUEMENT en JSON valide, sans texte avant ou après :
{{"outils": {json.dumps([t['name'] for t in outils_filtres])}, "raison": "explication courte en français"}}

Les valeurs possibles pour "outils" :
{json.dumps([t['name'] for t in outils_filtres])}
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.1
        )
        contenu = response.choices[0].message.content.strip()
        contenu = contenu.replace("```json", "").replace("```", "").strip()
        decision = json.loads(contenu)

        outils = decision.get("outils", [t["name"] for t in outils_filtres])
        raison = decision.get("raison", "Analyse recommandée")

        tools_registry = {tool["name"] for tool in all_tools}
        outils_valides = [o for o in outils if o in tools_registry]

        if not outils_valides:
            outils_valides = [t["name"] for t in outils_filtres]

        print(f"[AGENT ORCHESTRATEUR] Décision : {outils_valides} — {raison}")
        return {"outils": outils_valides, "raison": raison}

    except Exception as e:
        print(f"[AGENT ORCHESTRATEUR] Erreur : {e}")
        return {
            "outils": [t["name"] for t in outils_filtres],
            "raison": "Analyse complète par défaut"
        }


# ──────────────────────────────────────────────────────────────
# AGENT 2 — ANALYSEUR
# ──────────────────────────────────────────────────────────────

def agent_analyseur(cible: str, output_brut: str, scanners_used: list) -> str:
    print(f"[AGENT ANALYSEUR] Interprétation des résultats de {', '.join(scanners_used)}...")

    prompt = f"""Tu es un expert en cybersécurité chargé d'analyser des résultats de scans de sécurité.

Voici les résultats bruts des outils {', '.join(scanners_used)} sur la cible : {cible}

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


# ──────────────────────────────────────────────────────────────
# ROUTES FASTAPI
# ──────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def interface(request: Request, response: Response,
                    session_id: Optional[str] = Cookie(None)):
    # Créer un session_id unique si absent
    if not session_id:
        session_id = str(uuid.uuid4())
        response.set_cookie(
            key="session_id",
            value=session_id,
            max_age=30 * 24 * 3600,  # 30 jours
            httponly=True             # Sécurité : inaccessible depuis JS
        )
    return templates.TemplateResponse(request, "index.html")


@app.get("/session")
@app.get("/api/session")
def get_session(response: Response,
                session_id: Optional[str] = Cookie(None)):
    """Retourne le session_id actuel et l'assigne via cookie"""
    if not session_id:
        session_id = str(uuid.uuid4())
        response.set_cookie(
            key="session_id",
            value=session_id,
            max_age=30 * 24 * 3600,
            httponly=False  # Autorise la lecture depuis JS
        )
    return {"session_id": session_id}


@app.get("/health")
def health():
    return {
        "statut": "ok",
        "agents": ["orchestrateur", "analyseur"],
        "db":     "sqlite"
    }


@app.get("/tools")
def tools_list():
    return {
        "outils": get_all_tools(),
        "nombre": len(get_all_tools())
    }


@app.get("/historique")
@app.get("/api/historique")
def historique(limite: int = 10,
               session_id: Optional[str] = Cookie(None)):
    """Retourne les scans de la session courante uniquement"""
    if not session_id:
        return {"scans": []}
    return {"scans": get_historique(limite, session_id)}


@app.get("/historique/{scan_id}")
@app.get("/api/historique/{scan_id}")
def detail_scan(scan_id: int,
                session_id: Optional[str] = Cookie(None)):
    """Retourne un scan par ID — uniquement si appartient à la session"""
    scan = get_scan_par_id(scan_id, session_id)
    if not scan:
        return {"erreur": "Scan non trouvé ou accès refusé"}
    return scan


@app.get("/analyser")
@app.get("/api/analyser")
def analyser(cible: str, type_scan: str = "web",
             session_id_param: Optional[str] = None,
             session_id: Optional[str] = Cookie(None)):
    """
    Flux :
    1. Agent orchestrateur filtre les outils selon type_scan
    2. Chaque outil sélectionné exécute son scan
    3. Agent analyseur interprète les résultats
    4. Sauvegarde dans SQLite avec session_id
    5. Retour du rapport complet
    """

    # Priorité : paramètre de requête > cookie > générer un nouveau
    if session_id_param:
        session_id = session_id_param
    elif not session_id:
        session_id = str(uuid.uuid4())

    try:
        output_brut = ""
        findings = []
        scanners_used = []

        # ÉTAPE 1 : Agent orchestrateur
        decision = agent_orchestrateur(cible, type_scan)
        outils_choisis = decision["outils"]
        raison_orchestrateur = decision["raison"]
        print(f"[ORCHESTRATEUR] Outils choisis : {outils_choisis}")

        # ÉTAPE 2 : Lancement des outils
        for outil_name in outils_choisis:
            try:
                tool = get_tool(outil_name)

                if tool is None:
                    print(f"[ERREUR] Outil '{outil_name}' non trouvé")
                    continue

                print(f"[{outil_name.upper()}] Lancement du scan...")
                scanners_used.append(outil_name)

                raw_output = tool.run(cible)
                normalized_findings = tool.normalize(raw_output)
                findings.extend(normalized_findings)

                raw_str = "\n".join([
                    f"{a.get('risk', '?')} - {a.get('name', '?')}: {a.get('url', '?')}"
                    for a in raw_output
                ]) if isinstance(raw_output, list) else str(raw_output)

                output_brut += f"\n=== RÉSULTATS {outil_name.upper()} ===\n{raw_str or 'Aucun résultat'}"

            except Exception as e:
                print(f"[ERREUR] {outil_name.upper()} : {str(e)}")
                output_brut += f"\n=== ERREUR {outil_name.upper()} ===\n{str(e)}"

        if not findings:
            findings = [{
                "id":             "scan_0",
                "outil":          ", ".join(scanners_used) if scanners_used else "unknown",
                "titre":          "Scan terminé — aucune vulnérabilité détectée",
                "severite":       "low",
                "description":    output_brut[:200] if output_brut else "Aucun résultat",
                "recommandation": ""
            }]

        # ÉTAPE 3 : Agent analyseur
        synthese = agent_analyseur(cible, output_brut, scanners_used)

        # ÉTAPE 4 : Sauvegarder avec session_id
        scan_id = sauvegarder_scan(
            cible=cible,
            type_scan=type_scan,
            outils=outils_choisis,
            findings=findings,
            synthese=synthese,
            session_id=session_id
        )
        print(f"[DB] Scan #{scan_id} sauvegardé pour session {session_id[:8]}...")

        # ÉTAPE 5 : Rapport final
        return {
            "scan_id":        scan_id,
            "cible":          cible,
            "typae_scan":      type_scan,
            "outils_choisis": outils_choisis,
            "orchestrateur":  {
                "outils_choisis": outils_choisis,
                "raison":         raison_orchestrateur
            },
            "timestamp": datetime.now().isoformat(),
            "findings":  findings,
            "synthese":  synthese,
            "statut":    "success"
        }

    except Exception as e:
        print(f"[ANALYSER] Erreur globale : {e}")
        return {
            "scan_id":        None,
            "cible":          cible,
            "type_scan":      type_scan,
            "outils_choisis": [],
            "orchestrateur":  {"outils_choisis": [], "raison": "Erreur interne"},
            "timestamp":      datetime.now().isoformat(),
            "findings":       [],
            "synthese":       "Erreur interne : impossible de finaliser l'analyse.",
            "statut":         "error",
            "message":        str(e)
        }