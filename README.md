# orchestra-stage
stage PFE LST gi 
Plateforme d'analyse de sécurité automatisée pilotée par agents IA

## Description
ORCHESTRA reçoit une cible (URL, IP ou dépôt Git) et produit 
automatiquement un rapport de sécurité complet grâce à des 
agents IA (Groq LLaMA 3.3).

## Technologies
- Backend : Python + FastAPI
- Conteneurs : Docker + Docker Compose
- Agent IA : Groq LLaMA 3.3 70B
- Outils : ZAP, Nikto, Nmap, Semgrep
- Interface : HTML / CSS / JavaScript

## Lancement rapide
1. Cloner le repo
2. Créer un fichier `.env` :
   GROQ_API_KEY=ta_cle_groq_ici
3. Lancer :
   docker compose up --build
4. Ouvrir : http://localhost:8000

## Structure
- app/ — Backend FastAPI + Interface web
- deploy/ — Docker Compose
- dockerfiles/ — Dockerfiles
- tools/ — Wrappers outils de sécurité

## Auteur
El Bahy Khadija — PFE Génie Informatique
Faculté des Sciences et Techniques Settat
