"""
Test de bout en bout de l'agent LangGraph sur un incident exemple.

Usage :
    python -m agent.run
    python -m agent.run --incident "Description personnalisée de l'incident..."
"""

import argparse
import json

from agent.graph import build_agent_graph
from agent.state import AgentState

DEFAULT_INCIDENT = (
    "Un serveur Apache Struts version 2.5.30 montre un comportement anormal, "
    "avec des tentatives de connexion répétées depuis une IP inconnue."
)


def main():
    parser = argparse.ArgumentParser(description="Teste l'agent SecureRAG de bout en bout.")
    parser.add_argument("--incident", type=str, default=DEFAULT_INCIDENT, help="Description de l'incident.")
    args = parser.parse_args()

    print(f"Incident : {args.incident}\n")
    print("Exécution de l'agent...\n")

    graph = build_agent_graph()
    result = graph.invoke(AgentState(incident_description=args.incident))

    final_analysis = result["final_analysis"]

    print("=" * 70)
    print("ANALYSE FINALE")
    print("=" * 70)
    print(json.dumps(final_analysis.model_dump(), indent=2, ensure_ascii=False))

    print("\n" + "=" * 70)
    print("DÉTAIL DU RAISONNEMENT")
    print("=" * 70)
    entities = result.get("entities")
    if entities:
        print(f"\nEntités extraites :")
        print(json.dumps(entities.model_dump(), indent=2, ensure_ascii=False))

    print(f"\nRaffinements de requête effectués : {result.get('refinement_count', 0)}")
    print(f"CVE trouvées ({len(result.get('cve_results', []))}) :")
    for r in result.get("cve_results", []):
        print(f"  - {r['cve_id']} (score: {r['similarity_score']}, sévérité: {r['cvss_severity']})")
    print(f"Logs corrélés ({len(result.get('log_results', []))}) :")
    for l in result.get("log_results", [])[:5]:
        print(f"  - [{l['timestamp']}] {l['message']}")


if __name__ == "__main__":
    main()
