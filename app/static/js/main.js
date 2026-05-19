// ORCHESTRA — Interface utilisateur

let scanType = 'web';
let dernierResultat = null;
let sessionId = null; // Variable globale pour session_id

// ─── 0. INITIALISER LA SESSION AU CHARGEMENT
async function initialiserSession() {
  try {
    const response = await fetch('/api/session', {
      credentials: 'include'
    });
    if (response.ok) {
      const data = await response.json();
      sessionId = data.session_id;
      localStorage.setItem('orchestra_session', sessionId);
      console.log(`✓ Session initialisée : ${sessionId.substring(0, 8)}...`);
    }
  } catch (erreur) {
    console.error('Erreur lors de l\'initialisation de la session :', erreur);
  }
}

// Initialiser la session au chargement de la page
document.addEventListener('DOMContentLoaded', initialiserSession);

// ─── CONFIG CENTRALISÉE
const CONFIG = {
  types: {
    web:   { placeholder: 'http://testphp.vulnweb.com', outils: ['zap', 'nikto'] },
    infra: { placeholder: 'scanme.nmap.org',            outils: ['nmap']         },
    code:  { placeholder: '/chemin/vers/repo',           outils: ['semgrep']      }
  },
  etapes: {
    web:   ['Initialisation des conteneurs Docker', 'Lancement ZAP — scan vulnérabilités web',   'Lancement Nikto — audit configuration serveur', 'Normalisation des résultats JSON', 'Analyse IA via Groq LLaMA 3.3', 'Génération du rapport final'],
    infra: ['Initialisation des conteneurs Docker', 'Lancement Nmap — scan ports et services',   'Détection des versions et OS',                  'Normalisation des résultats JSON', 'Analyse IA via Groq LLaMA 3.3', 'Génération du rapport final'],
    code:  ['Initialisation des conteneurs Docker', 'Lancement Semgrep — analyse statique',      'Détection des patterns vulnérables',            'Normalisation des résultats JSON', 'Analyse IA via Groq LLaMA 3.3', 'Génération du rapport final']
  },
  severite: {
    high:   { classe: 'sev-high',   label: 'CRITIQUE' },
    medium: { classe: 'sev-medium', label: 'MOYEN'    },
    low:    { classe: 'sev-low',    label: 'FAIBLE'   }
  }
};

// ─── 1. CHANGER LE TYPE DE SCAN
function selectType(type, bouton) {
  scanType = type;
  document.querySelectorAll('.type-btn').forEach(b => b.classList.remove('active'));
  bouton.classList.add('active');
  document.getElementById('targetInput').placeholder = CONFIG.types[type]?.placeholder ?? 'Saisir une cible';
  mettreAJourBadges(CONFIG.types[type]?.outils ?? []);
}

// ─── 2. METTRE À JOUR LES BADGES
function mettreAJourBadges(outilsActifs) {
  ['zap', 'nikto', 'nmap', 'semgrep'].forEach(outil => {
    document.getElementById(`tool-${outil}`)
      ?.classList.toggle('active', outilsActifs.includes(outil));
  });
}

// ─── 3. METTRE À JOUR LES ÉTAPES
function mettreAJourEtapes(type) {
  (CONFIG.etapes[type] ?? CONFIG.etapes.web).forEach((texte, i) => {
    const el = document.getElementById(`step${i + 1}`);
    if (!el) return;
    el.classList.remove('active', 'done');
    el.querySelector('.step-icon').textContent = '◎';
    el.childNodes[1].textContent = texte;
  });
}

// ─── 4. LANCER LE SCAN
async function lancerScan() {
  const cible = document.getElementById('targetInput').value.trim();
  if (!cible) { alert('Veuillez saisir une cible.'); return; }

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.textContent = 'Analyse en cours...';

  mettreAJourEtapes(scanType);
  document.getElementById('progressCard').classList.add('visible');
  document.getElementById('resultsCard').classList.remove('visible');

  for (let i = 1; i <= 6; i++) await etape(i, Math.round((i / 6) * 100));

  try {
    // Inclure session_id dans l'URL (fallback si cookie manque)
    const sessionParam = sessionId ? `&session_id=${encodeURIComponent(sessionId)}` : '';
    const url = `/api/analyser?cible=${encodeURIComponent(cible)}&type_scan=${encodeURIComponent(scanType)}${sessionParam}`;
    const response = await fetch(url, {
      credentials: 'include'
    });

    if (!response.ok) throw new Error(`Erreur serveur ${response.status}`);

    const data = await response.json();
    dernierResultat = data;
    afficherResultats(data);
    await chargerHistorique(); // ← rafraîchir l'historique après le scan

  } catch (erreur) {
    alert(`Erreur : ${erreur.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ Lancer le scan';
  }
}

// ─── 5. SIMULER UNE ÉTAPE
async function etape(numero, pourcentage) {
  document.getElementById('progressPct').textContent = `${pourcentage}%`;
  document.getElementById('progressBar').style.width = `${pourcentage}%`;
  const el = document.getElementById(`step${numero}`);
  if (el) { el.classList.add('active'); el.querySelector('.step-icon').textContent = '▶'; }
  await new Promise(r => setTimeout(r, 800));
  if (el) { el.classList.remove('active'); el.classList.add('done'); el.querySelector('.step-icon').textContent = '✓'; }
}

// ─── 6. AFFICHER LES RÉSULTATS
function afficherResultats(data) {
  mettreAJourBadges(data.outils_choisis ?? []);

  const findings = data.findings ?? [];
  const compter = sev => findings.filter(f => f.severite === sev).length;
  document.getElementById('scoreHigh').textContent   = compter('high');
  document.getElementById('scoreMedium').textContent = compter('medium');
  document.getElementById('scoreLow').textContent    = compter('low');

  const liste = document.getElementById('findingsList');
  liste.replaceChildren();

  findings.forEach(f => {
    const config = CONFIG.severite[f.severite] ?? CONFIG.severite.low;

    const finding = document.createElement('div');
    finding.className = 'finding';

    const badge = document.createElement('span');
    badge.className = `finding-sev ${config.classe}`;
    badge.textContent = config.label;

    const content = document.createElement('div');
    content.className = 'finding-content';

    const titre = document.createElement('div');
    titre.className = 'finding-title';
    titre.textContent = f.titre;

    const desc = document.createElement('div');
    desc.className = 'finding-desc';
    desc.textContent = f.description;

    content.append(titre, desc);
    finding.append(badge, content);
    liste.append(finding);
  });

  document.getElementById('aiText').textContent = data.synthese ?? 'Pas de synthèse disponible';
  document.getElementById('resultsCard').classList.add('visible');
}

// ─── 7. EXPORT JSON
function exportJSON() {
  if (!dernierResultat) { alert('Aucun résultat à exporter.'); return; }
  const blob = new Blob([JSON.stringify({
    cible:    document.getElementById('targetInput').value,
    type:     scanType,
    date:     new Date().toLocaleString('fr-FR'),
    outils:   dernierResultat.outils_choisis ?? [],
    findings: dernierResultat.findings ?? [],
    synthese: dernierResultat.synthese ?? ''
  }, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `rapport_orchestra_${Date.now()}.json`;
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

// ─── 8. CHARGER L'HISTORIQUE
async function chargerHistorique() {
  try {
    const response = await fetch('/api/historique?limite=5', {
      credentials: 'include'
    });
    const data = await response.json();
    afficherHistorique(data.scans ?? []);
  } catch (e) {
    console.error('Historique indisponible', e);
  }
}

// ─── 9. AFFICHER L'HISTORIQUE
function afficherHistorique(scans) {
  const liste = document.getElementById('historyList');
  if (!liste) return;
  liste.replaceChildren();

  if (scans.length === 0) {
    const vide = document.createElement('p');
    vide.textContent = 'Aucun scan effectué pour le moment.';
    liste.append(vide);
    return;
  }

  scans.forEach(scan => {
    const item = document.createElement('div');
    item.className = 'history-item';
    item.onclick = () => chargerScanHistorique(scan.id);

    const date = new Date(scan.timestamp).toLocaleString('fr-FR');

    // Créer les éléments sans innerHTML
    const cibleEl = document.createElement('div');
    cibleEl.className = 'history-cible';
    cibleEl.textContent = scan.cible;

    const metaEl = document.createElement('div');
    metaEl.className = 'history-meta';
    metaEl.textContent = `${date} — ${scan.type_scan.toUpperCase()}`;

    const scoresEl = document.createElement('div');
    scoresEl.className = 'history-scores';

    const critique = document.createElement('span');
    critique.className = 'sev-high';
    critique.textContent = `${scan.nb_critique} critique`;

    const moyen = document.createElement('span');
    moyen.className = 'sev-medium';
    moyen.textContent = `${scan.nb_moyen} moyen`;

    const faible = document.createElement('span');
    faible.className = 'sev-low';
    faible.textContent = `${scan.nb_faible} faible`;

    scoresEl.append(critique, moyen, faible);
    item.append(cibleEl, metaEl, scoresEl);
    liste.append(item);
  });
}

// ─── 10. RECHARGER UN ANCIEN SCAN
async function chargerScanHistorique(scanId) {
  try {
    const response = await fetch(`/api/historique/${scanId}`, {
      credentials: 'include'
    });
    const data = await response.json();
    if (data.erreur) { alert(data.erreur); return; }
    document.getElementById('targetInput').value = data.cible;
    afficherResultats(data);
    document.getElementById('progressCard').classList.remove('visible');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (e) {
    alert('Impossible de charger ce scan');
  }
}

// ─── INIT
mettreAJourBadges(CONFIG.types.web.outils);
chargerHistorique();