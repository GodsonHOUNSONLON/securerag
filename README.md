# SecureRAG

Agent IA d'investigation d'incidents de cybersécurité — RAG + LangGraph + MCP + évaluation automatisée.

## Setup rapide

```bash
# 1. Créer et activer l'environnement virtuel
python3.11 -m venv .venv
source .venv/bin/activate  # (.venv\Scripts\activate sur Windows)

# 2. Installer les dépendances
pip install -e ".[dev]"

# 3. Configurer les variables d'environnement
cp .env.example .env
# → éditer .env avec tes clés (NVD, Anthropic, Pinecone, Supabase)

# 4. Premier test d'ingestion NVD (mode rapide, 200 CVE max)
python -m ingestion.fetch_nvd --last-mod-days 30 --max-results 200
```

## Structure du projet

```
securerag/
├── ingestion/      # récupération et vectorisation NVD / MITRE ATT&CK
├── agent/          # agent LangGraph (orchestration multi-étapes)
├── mcp_server/     # serveur MCP custom (lookup_cve, search_logs)
├── api/            # API FastAPI
├── evals/          # dataset et scripts d'évaluation (précision, hallucination, latence, coût)
└── ui/             # interface de démonstration Streamlit
```

## Statut

🚧 Projet en cours de développement — Semaine 1 (fondations : données, base vectorielle, premier agent simple).

## Notes

Toutes les données utilisées sont publiques (NVD, MITRE ATT&CK) ou générées synthétiquement. Aucune donnée privée ou confidentielle n'est utilisée.
