"""
Schéma d'état partagé entre les nœuds du graphe LangGraph, et modèles Pydantic
de sortie structurée de l'agent.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field


class IncidentAnalysis(BaseModel):
    """Sortie structurée finale de l'agent (telle que définie dans la spec du projet)."""

    cve_identifiees: list[str] = Field(description="Liste des identifiants CVE jugés pertinents.")
    severite: Literal["critique", "haute", "moyenne", "basse", "indéterminée"] = Field(
        description="Niveau de sévérité global évalué pour l'incident."
    )
    tactique_attack_probable: str | None = Field(
        default=None, description="Tactique/technique MITRE ATT&CK probable, si identifiable."
    )
    plan_remediation: str = Field(description="Plan de remédiation recommandé.")
    niveau_confiance: float = Field(ge=0.0, le=1.0, description="Confiance de l'agent dans son analyse (0 à 1).")
    sources_utilisees: list[str] = Field(
        default_factory=list, description="Sources utilisées pour construire la réponse (CVE, logs, etc.)."
    )


class IncidentEntities(BaseModel):
    """Sortie structurée du nœud d'analyse initiale."""

    produit: str | None = Field(default=None, description="Produit ou technologie mentionné dans l'incident.")
    version: str | None = Field(default=None, description="Version du produit, si mentionnée.")
    comportement_observe: str = Field(description="Résumé du comportement anormal décrit dans l'incident.")
    indicateurs: list[str] = Field(
        default_factory=list,
        description="Indicateurs concrets à rechercher dans les logs (IP, endpoint, pattern...).",
    )
    requete_recherche_cve: str = Field(
        description="Requête en langage naturel optimisée pour la recherche sémantique de CVE."
    )


class AgentState(BaseModel):
    """État partagé, transmis et enrichi d'un nœud à l'autre du graphe."""

    model_config = {"arbitrary_types_allowed": True}

    incident_description: str
    entities: IncidentEntities | None = None
    cve_results: list[dict[str, Any]] = Field(default_factory=list)
    log_results: list[dict[str, Any]] = Field(default_factory=list)
    refinement_count: int = 0
    max_refinements: int = 2
    final_analysis: IncidentAnalysis | None = None
