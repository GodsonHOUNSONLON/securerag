"""
Construction du graphe LangGraph de l'agent SecureRAG.

Flux :
    analyze_incident -> search_cve -> [refine_query -> search_cve]* -> search_logs -> synthesize

Usage :
    from agent.graph import build_agent_graph
    graph = build_agent_graph()
    result = graph.invoke({"incident_description": "..."})
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from agent.nodes import (
    analyze_incident,
    refine_query_node,
    route_after_cve_search,
    search_cve_node,
    search_logs_node,
    synthesize_node,
)
from agent.state import AgentState


def build_agent_graph():
    graph = StateGraph(AgentState)

    graph.add_node("analyze_incident", analyze_incident)
    graph.add_node("search_cve", search_cve_node)
    graph.add_node("refine_query", refine_query_node)
    graph.add_node("search_logs", search_logs_node)
    graph.add_node("synthesize", synthesize_node)

    graph.set_entry_point("analyze_incident")
    graph.add_edge("analyze_incident", "search_cve")

    graph.add_conditional_edges(
        "search_cve",
        route_after_cve_search,
        {
            "refine": "refine_query",
            "continue": "search_logs",
        },
    )
    graph.add_edge("refine_query", "search_cve")

    graph.add_edge("search_logs", "synthesize")
    graph.add_edge("synthesize", END)

    return graph.compile()
