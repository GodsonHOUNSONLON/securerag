"""
Test rapide des outils lookup_cve et search_logs, en appelant directement les
fonctions sous-jacentes (sans passer par le protocole MCP / un client MCP).
Utile pour valider la logique avant de brancher un vrai client (agent LangGraph
ou l'inspecteur MCP officiel).

Usage :
    python -m mcp_server.test_tools
"""

from mcp_server.server import lookup_cve, search_logs


def print_section(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():
    print_section("TEST 1 : lookup_cve - recherche générique")
    results = lookup_cve("Apache Struts remote code execution")
    for r in results:
        print(f"[{r['similarity_score']}] {r['cve_id']} (sévérité: {r['cvss_severity']})")
        print(f"    {r['description'][:150]}...")

    print_section("TEST 2 : lookup_cve - avec filtre produit")
    results = lookup_cve("remote code execution vulnerability", product="apache struts", top_k=3)
    for r in results:
        print(f"[{r['similarity_score']}] {r['cve_id']} (sévérité: {r['cvss_severity']})")
        print(f"    {r['description'][:150]}...")

    print_section("TEST 3 : search_logs - recherche par pattern")
    results = search_logs("port scan")
    print(f"{len(results)} logs trouvés pour 'port scan'")
    for log in results[:5]:
        print(f"  [{log['timestamp']}] {log['message']}")

    print_section("TEST 4 : search_logs - recherche avec filtre temporel")
    results = search_logs("failed login", timeframe="7d")
    print(f"{len(results)} logs trouvés pour 'failed login' sur les 7 derniers jours")
    for log in results[:5]:
        print(f"  [{log['timestamp']}] {log['message']}")

    print_section("TEST 5 : search_logs - pattern lié au scénario Struts")
    results = search_logs("struts")
    print(f"{len(results)} logs trouvés pour 'struts'")
    for log in results[:5]:
        print(f"  [{log['timestamp']}] {log['message']}")

    print("\n" + "=" * 70)
    print("Tests terminés.")
    print("=" * 70)


if __name__ == "__main__":
    main()
