# --- ÉTAPE 1 : Le Backend (FastAPI) ---
FROM python:3.11-slim as backend-builder

WORKDIR /app

# Copier et installer les dépendances du backend
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le code
COPY . .

# Déplacer les fichiers du frontend là où FastAPI peut les lire automatiquement sans config
# On triche proprement : on met ton index.html dans le dossier static de FastAPI
RUN mkdir -p app/static && cp -r frontend/* app/static/ || true

# Exposer le port obligatoire de Hugging Face
EXPOSE 7860

# Lancer FastAPI sur le bon port
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]