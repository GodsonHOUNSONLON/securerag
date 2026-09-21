"""
Exécute l'agent SecureRAG sur chaque cas du dataset d'évaluation et calcule
les métriques : précision de récupération, taux de hallucination, cohérence
de sévérité, taux de "je ne sais pas" approprié sur les cas pièges, latence,
et un coût approximatif.

Usage :
    python -m evals.run_eval --dataset evals/dataset.jsonl --output evals/results.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from agent.graph import build_agent_graph
from agent.state import AgentState

# Estimation grossière du coût : ~$3/M tokens input, ~$15/M tokens output
# (tarifs indicatifs Claude Sonnet), avec un décompte de tokens approximé par
# 1 token ≈ 4 caractères. C'est une ESTIMATION, pas une mesure exacte — la
# mesure exacte nécessiterait de capturer les usage_metadata de chaque appel
# LLM individuellement (voir note dans le README des evals).
APPROX_INPUT_COST_PER_TOKEN = 3.0 / 1_000_000
APPROX_OUTPUT_COST_PER_TOKEN = 15.0 / 1_000_000
CHARS_PER_TOKEN_ESTIMATE = 4


def load_dataset(path: Path) -> list[dict[str, Any]]:
    cases = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def evaluate_case(graph, case: dict[str, Any]) -> dict[str, Any]:
    start = time.perf_counter()
    result = graph.invoke(AgentState(incident_description=case["incident_description"]))
    latency = time.perf_counter() - start

    final_analysis = result["final_analysis"]
    cve_results = result.get("cve_results", [])
    retrieved_ids = {r["cve_id"] for r in cve_results}

    predicted_ids = set(final_analysis.cve_identifiees)
    expected_ids = set(case["expected_cve_ids"])

    # --- Précision de récupération : la bonne CVE était-elle dans le top-k retrouvé ? ---
    retrieval_hit = bool(expected_ids & retrieved_ids) if expected_ids else None

    # --- Hallucination : l'agent a-t-il cité une CVE qu'il n'a jamais récupérée ? ---
    hallucinated_ids = predicted_ids - retrieved_ids
    hallucinated = len(hallucinated_ids) > 0

    # --- Cas piège : l'agent a-t-il correctement renvoyé une liste vide ? ---
    trap_handled_correctly = None
    if case.get("is_trap"):
        trap_handled_correctly = len(predicted_ids) == 0

    # --- Cohérence de sévérité ---
    severity_match = final_analysis.severite == case["expected_severity"]

    # --- Coût approximatif (grossier, voir note en tête de fichier) ---
    full_text = case["incident_description"] + json.dumps(final_analysis.model_dump(), ensure_ascii=False)
    approx_tokens = len(full_text) // CHARS_PER_TOKEN_ESTIMATE
    approx_cost_usd = approx_tokens * (APPROX_INPUT_COST_PER_TOKEN + APPROX_OUTPUT_COST_PER_TOKEN) / 2

    return {
        "case_id": case["id"],
        "is_trap": case.get("is_trap", False),
        "expected_cve_ids": list(expected_ids),
        "predicted_cve_ids": list(predicted_ids),
        "retrieved_cve_ids": list(retrieved_ids),
        "retrieval_hit": retrieval_hit,
        "hallucinated": hallucinated,
        "hallucinated_ids": list(hallucinated_ids),
        "trap_handled_correctly": trap_handled_correctly,
        "expected_severity": case["expected_severity"],
        "predicted_severity": final_analysis.severite,
        "severity_match": severity_match,
        "niveau_confiance": final_analysis.niveau_confiance,
        "refinement_count": result.get("refinement_count", 0),
        "latency_seconds": round(latency, 2),
        "approx_cost_usd": round(approx_cost_usd, 6),
    }


def summarize(all_results: list[dict[str, Any]]) -> dict[str, Any]:
    non_trap = [r for r in all_results if not r["is_trap"]]
    traps = [r for r in all_results if r["is_trap"]]

    retrieval_hits = [r["retrieval_hit"] for r in non_trap if r["retrieval_hit"] is not None]
    precision_at_k = sum(retrieval_hits) / len(retrieval_hits) if retrieval_hits else None

    hallucination_rate = sum(r["hallucinated"] for r in all_results) / len(all_results)

    severity_matches = [r["severity_match"] for r in non_trap]
    severity_coherence = sum(severity_matches) / len(severity_matches) if severity_matches else None

    trap_correct = [r["trap_handled_correctly"] for r in traps if r["trap_handled_correctly"] is not None]
    trap_success_rate = sum(trap_correct) / len(trap_correct) if trap_correct else None

    latencies = [r["latency_seconds"] for r in all_results]
    avg_latency = sum(latencies) / len(latencies)
    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0]

    total_cost = sum(r["approx_cost_usd"] for r in all_results)
    avg_cost = total_cost / len(all_results)

    return {
        "n_cases": len(all_results),
        "n_non_trap_cases": len(non_trap),
        "n_trap_cases": len(traps),
        "precision_retrieval_top_k": round(precision_at_k, 3) if precision_at_k is not None else None,
        "hallucination_rate": round(hallucination_rate, 3),
        "severity_coherence_rate": round(severity_coherence, 3) if severity_coherence is not None else None,
        "trap_success_rate": round(trap_success_rate, 3) if trap_success_rate is not None else None,
        "avg_latency_seconds": round(avg_latency, 2),
        "p95_latency_seconds": round(p95_latency, 2),
        "avg_approx_cost_usd": round(avg_cost, 6),
        "total_approx_cost_usd": round(total_cost, 4),
    }


def main():
    parser = argparse.ArgumentParser(description="Exécute la suite d'évaluation SecureRAG.")
    parser.add_argument("--dataset", type=Path, default=Path("evals/dataset.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("evals/results.json"))
    args = parser.parse_args()

    cases = load_dataset(args.dataset)
    print(f"{len(cases)} cas chargés depuis {args.dataset}\n")

    graph = build_agent_graph()

    all_results = []
    for i, case in enumerate(cases, start=1):
        print(f"[{i}/{len(cases)}] Évaluation de {case['id']}...")
        result = evaluate_case(graph, case)
        all_results.append(result)
        status = "✅" if not result["hallucinated"] else "⚠️ HALLUCINATION"
        print(f"    {status} | sévérité: {result['predicted_severity']} "
              f"(attendu: {result['expected_severity']}) | latence: {result['latency_seconds']}s")

    summary = summarize(all_results)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        json.dump({"summary": summary, "cases": all_results}, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 70)
    print("RÉSUMÉ DE L'ÉVALUATION")
    print("=" * 70)
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print(f"\nRésultats détaillés écrits dans {args.output}")


if __name__ == "__main__":
    main()
