# SecureRAG

Agent IA d'investigation d'incidents de cybersécurité — RAG + LangGraph + MCP + évaluation automatisée.

## Setup rapide

```bash
# 1. Créer et activer l'environnement virtuel
python3.11 -m venv .venv
source .venv/bin/activate  # (.venv\Scripts\activate sur Windows)

# 2. Installer les dépendances
pip install -e ".[dev]"

# En environnement CPU sans GPU dédié (ex. laptop sans carte graphique dédiée),
# installer PyTorch en version CPU-only avant le reste réduit fortement la taille
# de l'installation :
# pip install torch --index-url https://download.pytorch.org/whl/cpu
# pip install -e ".[dev]"

# 3. Configurer les variables d'environnement
cp .env.example .env
# → éditer .env avec tes clés (NVD, Anthropic, Pinecone, Supabase)

# 4. Ingestion des CVE depuis l'API NVD
# --last-mod-days : CVE modifiées récemment (inclut d'anciennes CVE republiées)
# --pub-days      : CVE publiées récemment (vraies nouvelles vulnérabilités, max 120 jours)
python -m ingestion.fetch_nvd --last-mod-days 120 --max-results 2000
python -m ingestion.fetch_nvd --pub-days 120 --max-results 1000

# 5. Vectorisation et indexation dans Pinecone
python -m ingestion.build_vectorstore

# 6. Test rapide de recherche sémantique
python -m ingestion.test_search "Apache Struts vulnerability"
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

## Pipeline de vectorisation (RAG)

- **Modèle d'embedding** : [`BAAI/bge-base-en-v1.5`](https://huggingface.co/BAAI/bge-base-en-v1.5), exécuté en local via `sentence-transformers` (CPU). Choisi pour éviter une dépendance API supplémentaire (pas de compte/clé tiers) tout en gardant un bon niveau de qualité de retrieval, avec des contraintes matérielles modestes (pas de GPU dédié).
- **Base vectorielle** : Pinecone (serverless, index `securerag-cve`, dimension 768, métrique cosinus).
- **Corpus actuel** : ~3200 CVE, composées d'un mélange de CVE historiques bien documentées (utiles pour construire un dataset d'évaluation avec ground truth fiable) et de CVE effectivement publiées sur les 4 derniers mois de 2026 (représentatif d'un usage SOC actuel).
- **Limite connue** : le corpus n'est pas exhaustif — il ne couvre ni l'intégralité de l'historique NVD (378k+ CVE au total) ni un flux temps réel. Un déploiement en production interrogerait un flux NVD continu plutôt qu'un instantané.
- **Idempotence** : l'ingestion (`fetch_nvd.py`) comme l'indexation (`build_vectorstore.py`) sont idempotentes — relancer les scripts n'écrit ni ne duplique les CVE déjà présentes.

## Statut

✅ Semaine 1 terminée — pipeline RAG fonctionnel de bout en bout : ingestion NVD, chunking, embeddings, indexation Pinecone, recherche sémantique validée.

🚧 En cours — Semaine 2 : agent LangGraph multi-étapes et serveur MCP custom (`lookup_cve`, `search_logs`).

## Notes

Toutes les données utilisées sont publiques (NVD, MITRE ATT&CK) ou générées synthétiquement. Aucune donnée privée ou confidentielle n'est utilisée.
