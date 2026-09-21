"""
Implémentation des nœuds du graphe LangGraph.

Note d'architecture : le serveur MCP (mcp_server/server.py) expose lookup_cve
et search_logs comme un vrai service MCP, utilisable par n'importe quel client
MCP (Claude Desktop, etc.) — c'est la brique différenciante à présenter en
entretien. Pour la boucle interne de l'agent, on importe directement les
fonctions Python sous-jacentes plutôt que de passer par le protocole MCP
complet (latence réseau inutile pour un appel in-process). Un vrai
déploiement multi-services utiliserait un client MCP ici à la place.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic

from agent.state import AgentState, IncidentAnalysis, IncidentEntities
from mcp_server.server import lookup_cve, search_logs

load_dotenv()

MODEL_NAME = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")

# Seuil de similarité (score cosinus Pinecone) en-dessous duquel on considère
# le retrieval CVE peu fiable et on tente un raffinement de la requête.
CVE_CONFIDENCE_THRESHOLD = 0.55


def _get_llm(structured_output_model: type):
    llm = ChatAnthropic(model=MODEL_NAME, temperature=0)
    return llm.with_structured_output(structured_output_model)


# --- Nœud 1 : analyse initiale ---

ANALYSIS_PROMPT = """Tu es un analyste SOC senior. Extrait les informations clés de la description \
d'incident suivante, pour préparer une recherche de vulnérabilités (CVE) et de logs de sécurité.

Description de l'incident :
{incident_description}

Identifie le produit/technologie concerné, sa version si mentionnée, le comportement anormal observé, \
et formule une requête en langage naturel optimisée pour une recherche sémantique de CVE pertinentes.

Pour les indicateurs : fournis des MOTS-CLÉS COURTS et TECHNIQUES (1 à 3 mots chacun, en anglais si le \
terme est plus naturel ainsi, ex: "port scan", "failed login", "struts", "brute force", une IP, un nom \
d'endpoint) adaptés à une recherche par mot-clé dans des logs bruts. JAMAIS de phrase complète — ces \
indicateurs seront utilisés tels quels comme motif de recherche exact, pas interprétés sémantiquement."""


def analyze_incident(state: AgentState) -> dict:
    llm = _get_llm(IncidentEntities)
    prompt = ANALYSIS_PROMPT.format(incident_description=state.incident_description)
    entities: IncidentEntities = llm.invoke(prompt)
    return {"entities": entities}


# --- Nœud 2 : recherche CVE ---

def search_cve_node(state: AgentState) -> dict:
    entities = state.entities
    assert entities is not None, "search_cve_node appelé avant analyze_incident"

    results = lookup_cve(
        query=entities.requete_recherche_cve,
        product=entities.produit,
        top_k=5,
    )
    return {"cve_results": results}


# --- Nœud 2bis : raffinement de la requête (si confiance faible) ---

REFINEMENT_PROMPT = """La recherche de CVE précédente n'a pas donné de résultats suffisamment pertinents \
pour l'incident suivant. Reformule une requête de recherche plus large ou différente (synonymes, \
termes techniques alternatifs, sans filtre de produit trop restrictif).

Description de l'incident :
{incident_description}

Requête précédente : {previous_query}

Réponds uniquement avec la nouvelle requête de recherche, en langage naturel, sans autre texte."""


def refine_query_node(state: AgentState) -> dict:
    entities = state.entities
    assert entities is not None

    llm = ChatAnthropic(model=MODEL_NAME, temperature=0.3)
    prompt = REFINEMENT_PROMPT.format(
        incident_description=state.incident_description,
        previous_query=entities.requete_recherche_cve,
    )
    new_query = llm.invoke(prompt).content.strip()

    updated_entities = entities.model_copy(update={"requete_recherche_cve": new_query, "produit": None})
    return {"entities": updated_entities, "refinement_count": state.refinement_count + 1}


# --- Routage conditionnel : raffiner ou continuer ---

def route_after_cve_search(state: AgentState) -> str:
    if not state.cve_results:
        best_score = 0.0
    else:
        best_score = max(r.get("similarity_score", 0.0) for r in state.cve_results)

    if best_score < CVE_CONFIDENCE_THRESHOLD and state.refinement_count < state.max_refinements:
        return "refine"
    return "continue"


# --- Nœud 3 : recherche logs ---

def search_logs_node(state: AgentState) -> dict:
    """
    search_logs ne fait qu'un match de mot-clé exact (pas de recherche sémantique),
    donc on essaie plusieurs candidats plutôt qu'un seul, et on fusionne/déduplique
    les résultats. Un seul indicateur mal choisi ne doit pas faire échouer toute la
    recherche.
    """
    entities = state.entities
    assert entities is not None

    candidates = list(entities.indicateurs)
    if entities.produit:
        candidates.append(entities.produit)

    seen_keys: set[tuple[str, str]] = set()
    merged_results: list[dict] = []

    for pattern in candidates:
        if not pattern or len(pattern) > 40:  # évite les phrases trop longues glissées par erreur
            continue
        results = search_logs(pattern=pattern, timeframe="30d", max_results=20)
        for r in results:
            key = (r["timestamp"], r["message"])
            if key not in seen_keys:
                seen_keys.add(key)
                merged_results.append(r)

    merged_results.sort(key=lambda l: l["timestamp"], reverse=True)
    return {"log_results": merged_results[:20]}


# --- Nœud 4 : synthèse finale ---

SYNTHESIS_PROMPT = """Tu es un analyste SOC senior. Synthétise une analyse d'incident structurée à partir \
des éléments suivants.

Description de l'incident :
{incident_description}

CVE potentiellement pertinentes trouvées (recherche sémantique) :
{cve_results}

Logs de sécurité corrélés trouvés :
{log_results}

Consignes :
- Ne cite AUCUN identifiant CVE, nulle part dans ta réponse (y compris dans le plan de remédiation), \
s'il n'est pas explicitement listé dans les résultats de recherche fournis ci-dessus. Cette règle \
s'applique à tout le texte généré, pas seulement au champ cve_identifiees.
- Si aucune CVE des résultats ne correspond vraiment à l'incident, indique une liste vide et une \
confiance basse plutôt que d'inventer ou de citer une CVE connue de ta mémoire générale.
- Si tu veux recommander de vérifier les CVE connues pour ce produit, formule-le sans numéro précis \
(ex: "vérifier les avis de sécurité officiels du vendeur pour les versions concernées") plutôt que de \
citer un identifiant CVE non vérifié par la recherche.
- IMPORTANT pour la sévérité : si tu identifies dans cve_identifiees une CVE clairement correspondante \
dont la sévérité CVSS est indiquée dans les résultats ci-dessus, ALIGNE ta sévérité prédite sur cette \
sévérité CVSS plutôt que sur ton impression du ton de l'incident. N'escalade au-dessus de la sévérité \
CVSS connue que si l'incident apporte une preuve concrète et objective d'aggravation (ex: compromission \
confirmée, exfiltration de données avérée) — pas simplement parce que la description sonne grave. En \
l'absence de CVE clairement identifiée, évalue la sévérité prudemment à partir des seuls faits rapportés.
- Le niveau de confiance doit refléter honnêtement la qualité du match entre l'incident et les preuves disponibles.
- Le plan de remédiation doit être concret et actionnable pour un analyste SOC."""


def _format_cve_results(cve_results: list[dict]) -> str:
    if not cve_results:
        return "Aucun résultat."
    lines = []
    for r in cve_results:
        lines.append(
            f"- {r['cve_id']} (score similarité: {r['similarity_score']}, sévérité: {r['cvss_severity']}) : "
            f"{r['description'][:300]}"
        )
    return "\n".join(lines)


def _format_log_results(log_results: list[dict]) -> str:
    if not log_results:
        return "Aucun log corrélé trouvé."
    lines = [f"- [{l['timestamp']}] {l['message']}" for l in log_results[:15]]
    return "\n".join(lines)


def synthesize_node(state: AgentState) -> dict:
    llm = _get_llm(IncidentAnalysis)
    prompt = SYNTHESIS_PROMPT.format(
        incident_description=state.incident_description,
        cve_results=_format_cve_results(state.cve_results),
        log_results=_format_log_results(state.log_results),
    )
    analysis: IncidentAnalysis = llm.invoke(prompt)

    sources = []
    if state.cve_results:
        sources.append("Pinecone (base CVE, NVD)")
    if state.log_results:
        sources.append("Logs de sécurité synthétiques")
    analysis.sources_utilisees = sources

    return {"final_analysis": analysis}
