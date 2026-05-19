from tools.web.zap import ZapTool
from tools.web.nikto import NiktoTool
from tools.infra.nmap import NmapTool  

# ── REGISTRE CENTRAL ──────────────────────────────────────────
# Pour ajouter un nouvel outil : importer et ajouter à TOOLS
TOOLS: dict = {
    "zap":    ZapTool(),
    "nikto":  NiktoTool(),
     "nmap":  NmapTool(),  # "nmap":    NmapTool(),    ← décommenter quand prêt
    # "semgrep": SemgrepTool(), ← décommenter quand prêt
}

def get_tool(name: str):
    """Retourne un outil par son nom"""
    return TOOLS.get(name)

def get_all_tools() -> list:
    """Retourne la liste de tous les outils disponibles"""
    return [tool.to_info() for tool in TOOLS.values()]

def get_tools_by_category(category: str) -> list:
    """Retourne les outils d'une catégorie donnée (web, infra, code)"""
    return [
        tool for tool in TOOLS.values()
        if tool.category == category
    ]