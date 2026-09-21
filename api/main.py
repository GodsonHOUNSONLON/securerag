"""
API FastAPI exposant l'agent SecureRAG.

Endpoints :
- POST /analyze : soumet une description d'incident, retourne l'analyse structurée
- GET /health   : endpoint de santé pour le monitoring

Usage (dev) :
    uvicorn api.main:app --reload --port 8000

Usage (test rapide, une fois lancé) :
    curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" \
         -d '{"incident_description": "Un serveur Apache Struts 2.5.30 ..."}'
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent.graph import build_agent_graph
from agent.state import AgentState, IncidentAnalysis

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("securerag_api")

# L'agent (graphe LangGraph) est coûteux à construire mais léger une fois compilé ;
# les ressources vraiment coûteuses (modèle d'embedding, client Pinecone) sont
# chargées paresseusement au premier appel d'outil (voir mcp_server/server.py),
# donc on construit le graphe une seule fois au démarrage plutôt qu'à chaque requête.
_agent_graph = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _agent_graph
    logger.info("Construction du graphe de l'agent...")
    _agent_graph = build_agent_graph()
    logger.info("Agent prêt.")
    yield
    logger.info("Arrêt de l'API.")


app = FastAPI(
    title="SecureRAG API",
    description="Agent IA d'investigation d'incidents de cybersécurité.",
    version="0.1.0",
    lifespan=lifespan,
)


class AnalyzeRequest(BaseModel):
    incident_description: str = Field(
        ..., min_length=10, description="Description en langage naturel de l'incident à investiguer."
    )


class AnalyzeResponse(BaseModel):
    analysis: IncidentAnalysis
    processing_time_seconds: float


class HealthResponse(BaseModel):
    status: str
    agent_ready: bool


@app.get("/health", response_model=HealthResponse, tags=["monitoring"])
def health():
    return HealthResponse(status="ok", agent_ready=_agent_graph is not None)


@app.post("/analyze", response_model=AnalyzeResponse, tags=["analyse"])
def analyze(request: AnalyzeRequest):
    if _agent_graph is None:
        raise HTTPException(status_code=503, detail="Agent non initialisé, réessayez dans un instant.")

    start = time.perf_counter()
    try:
        result = _agent_graph.invoke(AgentState(incident_description=request.incident_description))
    except Exception as exc:
        logger.exception("Erreur lors de l'exécution de l'agent")
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'analyse : {exc}") from exc

    elapsed = time.perf_counter() - start

    final_analysis = result.get("final_analysis")
    if final_analysis is None:
        raise HTTPException(status_code=500, detail="L'agent n'a pas produit d'analyse finale.")

    return AnalyzeResponse(analysis=final_analysis, processing_time_seconds=round(elapsed, 2))
