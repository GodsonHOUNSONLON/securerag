"""
Serveur MCP custom pour SecureRAG.

Expose deux outils à l'agent :
- lookup_cve(query, product) : recherche sémantique de CVE via RAG (Pinecone)
- search_logs(pattern, timeframe) : recherche dans les logs de sécurité synthétiques

Usage (lancement du serveur en mode stdio, pour un client MCP) :
    python -m mcp_server.server

Pour un test rapide sans client MCP, voir mcp_server/test_tools.py qui appelle
directement les fonctions sous-jacentes.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer

load_dotenv()

EMBEDDING_MODEL_NAME = "BAAI/bge-base-en-v1.5"
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "
SYNTHETIC_LOGS_PATH = Path(os.getenv("SYNTHETIC_LOGS_PATH", "data/synthetic/security_logs.jsonl"))

mcp = MCPServer("securerag-mcp")

# --- Chargement paresseux du modèle et du client Pinecone (coûteux à instancier) ---
_embedding_model = None
_pinecone_index = None
_logs_cache: list[dict[str, Any]] | None = None


def get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        from sentence_transformers import SentenceTransformer
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME, device="cpu")
    return _embedding_model


def get_pinecone_index():
    global _pinecone_index
    if _pinecone_index is None:
        from pinecone import Pinecone
        api_key = os.getenv("PINECONE_API_KEY")
        index_name = os.getenv("PINECONE_INDEX_NAME", "securerag-cve")
        pc = Pinecone(api_key=api_key)
        _pinecone_index = pc.Index(index_name)
    return _pinecone_index


def get_logs() -> list[dict[str, Any]]:
    global _logs_cache
    if _logs_cache is None:
        if not SYNTHETIC_LOGS_PATH.exists():
            raise FileNotFoundError(
                f"Fichier de logs introuvable : {SYNTHETIC_LOGS_PATH}. "
                "Lance d'abord ingestion/generate_synthetic_logs.py."
            )
        logs = []
        with SYNTHETIC_LOGS_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(json.loads(line))
        _logs_cache = logs
    return _logs_cache


# --- Outil 1 : lookup_cve ---

@mcp.tool()
def lookup_cve(query: str, product: str | None = None, top_k: int = 5) -> list[dict[str, Any]]:
    """
    Recherche sémantique de CVE pertinentes dans la base vectorielle, à partir
    d'une description d'incident ou d'une requête en langage naturel.

    Args:
        query: Description de l'incident ou requête (ex: "Apache Struts remote code execution").
        product: Optionnel. Nom de produit/vendor pour affiner la recherche (ex: "apache struts").
        top_k: Nombre de résultats à retourner (défaut 5).

    Returns:
        Liste de CVE avec leur ID, score de similarité, sévérité CVSS, CWE et description.
    """
    model = get_embedding_model()
    index = get_pinecone_index()

    search_text = f"{query} {product}" if product else query
    embedding = model.encode(
        QUERY_INSTRUCTION + search_text,
        normalize_embeddings=True,
    ).tolist()

    # On récupère plus large que top_k pour pouvoir filtrer par produit ensuite si besoin
    fetch_k = top_k * 4 if product else top_k
    results = index.query(vector=embedding, top_k=fetch_k, include_metadata=True)

    matches = results.get("matches", [])

    if product:
        product_lower = product.lower()
        filtered = [m for m in matches if product_lower in m["metadata"].get("text", "").lower()]
        # Si le filtre produit ne retourne rien, on retombe sur les résultats non filtrés
        matches = filtered if filtered else matches

    matches = matches[:top_k]

    return [
        {
            "cve_id": m["metadata"]["cve_id"],
            "similarity_score": round(m["score"], 4),
            "cvss_score": m["metadata"].get("cvss_score"),
            "cvss_severity": m["metadata"].get("cvss_severity"),
            "cwe_ids": m["metadata"].get("cwe_ids", []),
            "published": m["metadata"].get("published"),
            "description": m["metadata"].get("text"),
        }
        for m in matches
    ]


# --- Outil 2 : search_logs ---

def _parse_timeframe(timeframe: str | None) -> datetime | None:
    """Parse '24h', '7d', '30d' etc. en date de début. Retourne None si pas de filtre."""
    if not timeframe:
        return None

    unit = timeframe[-1].lower()
    try:
        value = int(timeframe[:-1])
    except ValueError:
        return None

    now = datetime.now(timezone.utc)
    if unit == "h":
        return now - timedelta(hours=value)
    if unit == "d":
        return now - timedelta(days=value)
    if unit == "m":
        return now - timedelta(minutes=value)
    return None


@mcp.tool()
def search_logs(pattern: str, timeframe: str | None = None, max_results: int = 20) -> list[dict[str, Any]]:
    """
    Recherche dans les logs de sécurité synthétiques par mot-clé/pattern, avec
    filtre temporel optionnel.

    Args:
        pattern: Mot-clé ou motif à rechercher (ex: "port scan", "failed login", une IP, un endpoint).
        timeframe: Optionnel. Fenêtre temporelle relative (ex: "24h", "7d", "30d").
        max_results: Nombre maximum de résultats (défaut 20).

    Returns:
        Liste des entrées de logs correspondantes, triées par date décroissante.
    """
    logs = get_logs()
    pattern_lower = pattern.lower()
    since = _parse_timeframe(timeframe)

    matches = []
    for log in logs:
        # Recherche du pattern dans les champs textuels pertinents
        searchable = " ".join(
            str(log.get(field, "")) for field in ("message", "event", "endpoint", "source_ip", "user")
        ).lower()
        if pattern_lower not in searchable:
            continue

        if since is not None:
            log_ts = datetime.fromisoformat(log["timestamp"])
            if log_ts < since:
                continue

        matches.append(log)

    matches.sort(key=lambda l: l["timestamp"], reverse=True)
    return matches[:max_results]


if __name__ == "__main__":
    mcp.run(transport="stdio")
