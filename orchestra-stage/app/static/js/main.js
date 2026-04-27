// ─────────────────────────────────────────────
// ORCHESTRA — Interface utilisateur
// ─────────────────────────────────────────────

let scanType = 'web';

// ─── 1. CHANGER LE TYPE DE SCAN ───────────────
function selectType(type, bouton) {
  scanType = type;

  // Enlever active de tous les boutons
  document.querySelectorAll('.type-btn')
    .forEach(function(b) { b.classList.remove('active'); });

  // Activer le bouton cliqué
  bouton.classList.add('active');

  // Changer le placeholder
  var input = document.getElementById('targetInput');
  if (type === 'web')        input.placeholder = 'http://testphp.vulnweb.com';
  else if (type === 'infra') input.placeholder = 'scanme.nmap.org';
  else                       input.placeholder = '/chemin/vers/repo';
}


// ─── 2. LANCER LE SCAN ────────────────────────
async function lancerScan() {

  // Récupérer la cible
  var cible = document.getElementById('targetInput').value.trim();
  if (!cible) {
    alert('Veuillez saisir une cible.');
    return;
  }

  // Désactiver le bouton
  var btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.textContent = 'Analyse en cours...';

  // Afficher la progression
  document.getElementById('progressCard').classList.add('visible');
  document.getElementById('resultsCard').classList.remove('visible');

  // Simuler les étapes visuelles
  await etape(1, 15);
  await etape(2, 30);
  await etape(3, 50);
  await etape(4, 70);
  await etape(5, 85);
  await etape(6, 100);

  // Appel au backend FastAPI
  try {
    var response = await fetch('/analyser?cible=' + encodeURIComponent(cible));

    if (!response.ok) {
      throw new Error('Erreur serveur ' + response.status);
    }

    var data = await response.json();
    afficherResultats(data);

  } catch (erreur) {
    alert('Erreur : ' + erreur.message);
  }

  // Réactiver le bouton
  btn.disabled = false;
  btn.textContent = '▶ Lancer le scan';
}


// ─── 3. SIMULER UNE ÉTAPE ─────────────────────
async function etape(numero, pourcentage) {

  // Mettre à jour la barre
  document.getElementById('progressPct').textContent = pourcentage + '%';
  document.getElementById('progressBar').style.width = pourcentage + '%';

  // Marquer l'étape active
  var el = document.getElementById('step' + numero);
  if (el) {
    el.classList.add('active');
    el.querySelector('.step-icon').textContent = '▶';
  }

  // Attendre 800ms
  await new Promise(function(r) { setTimeout(r, 800); });

  // Marquer l'étape terminée
  if (el) {
    el.classList.remove('active');
    el.classList.add('done');
    el.querySelector('.step-icon').textContent = '✓';
  }
}


// ─── 4. AFFICHER LES RÉSULTATS ────────────────
function afficherResultats(data) {

  // Récupérer les données du backend
  var findings = data.findings || [];
  var synthese = data.synthese || 'Pas de synthèse disponible';

  // Compter par sévérité
  var high   = findings.filter(function(f) { return f.severite === 'high'; }).length;
  var medium = findings.filter(function(f) { return f.severite === 'medium'; }).length;
  var low    = findings.filter(function(f) { return f.severite === 'low'; }).length;

  // Afficher les compteurs
  document.getElementById('scoreHigh').textContent   = high;
  document.getElementById('scoreMedium').textContent = medium;
  document.getElementById('scoreLow').textContent    = low;

  // Construire la liste des findings
  var liste = document.getElementById('findingsList');
  liste.innerHTML = '';

  findings.forEach(function(f) {

    var classe = 'sev-low';
    var label  = 'FAIBLE';

    if (f.severite === 'high') {
      classe = 'sev-high';
      label  = 'CRITIQUE';
    } else if (f.severite === 'medium') {
      classe = 'sev-medium';
      label  = 'MOYEN';
    }

    liste.innerHTML += `
      <div class="finding">
        <span class="finding-sev ${classe}">${label}</span>
        <div class="finding-content">
          <div class="finding-title">${f.titre}</div>
          <div class="finding-desc">${f.description}</div>
        </div>
      </div>`;
  });

  // Afficher la synthèse Groq
  document.getElementById('aiText').textContent = synthese;

  // Montrer la section résultats
  document.getElementById('resultsCard').classList.add('visible');
}


// ─── 5. EXPORT JSON ───────────────────────────
function exportJSON() {

  var data = {
    cible:    document.getElementById('targetInput').value,
    type:     scanType,
    date:     new Date().toLocaleString('fr-FR'),
    synthese: document.getElementById('aiText').textContent
  };

  var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'rapport_orchestra.json';
  a.click();
}