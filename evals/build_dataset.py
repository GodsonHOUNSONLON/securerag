"""
Construit le dataset d'évaluation (20-30 cas) en échantillonnant de vraies CVE
du corpus Pinecone, puis en générant pour chacune un scénario d'incident SOC
réaliste (sans jamais nommer l'ID CVE ni le copier verbatim). Ajoute aussi des
cas "pièges" : incidents bénins ne correspondant à aucune vraie vulnérabilité,
pour vérifier que l'agent sait s'abstenir plutôt qu'halluciner.

Usage :
    python -m evals.build_dataset --n-cases 20 --output evals/dataset.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic

from mcp_server.server import lookup_cve

load_dotenv()

MODEL_NAME = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")

# Requêtes génériques couvrant des classes de vulnérabilités variées, pour
# échantillonner un corpus diversifié plutôt que des CVE toutes similaires.
SAMPLING_QUERIES = [
    "Apache web server vulnerability",
    "SQL injection web application",
    "remote code execution",
    "cross-site scripting XSS",
    "authentication bypass",
    "buffer overflow",
    "privilege escalation",
    "denial of service",
    "path traversal directory",
    "insecure deserialization",
    "server-side request forgery",
    "hardcoded credentials",
]

CVSS_TO_FR_SEVERITY = {
    "CRITICAL": "critique",
    "HIGH": "haute",
    "MEDIUM": "moyenne",
    "LOW": "basse",
}

INCIDENT_GENERATION_PROMPT = """Tu aides à construire un dataset d'évaluation pour un agent SOC. À partir \
de la description technique de vulnérabilité suivante, rédige un scénario d'incident de sécurité RÉALISTE \
tel qu'un analyste SOC pourrait le rapporter en observant des symptômes de cette vulnérabilité en cours \
d'exploitation (ou juste présente sur un système).

Description technique de la CVE (NE PAS citer l'ID CVE, NE PAS copier le texte verbatim) :
{cve_description}

Consignes :
- 2 à 3 phrases, en français, dans le style d'un rapport d'incident SOC (comportement observé, pas analyse déjà faite)
- Ne mentionne JAMAIS l'identifiant CVE
- Ne copie pas le texte de la description technique mot pour mot ; reformule comme un symptôme observé
- Reste réaliste et spécifique (nom de produit/version si pertinent, comportement anormal concret)

Réponds uniquement avec le scénario d'incident, sans autre texte."""


TRAP_CASES = [
    {
        "id": "trap_01",
        "incident_description": (
            "Un utilisateur signale que sa boîte mail Outlook est plus lente que d'habitude depuis ce matin, "
            "sans autre symptôme particulier."
        ),
        "expected_cve_ids": [],
        "expected_severity": "basse",
        "is_trap": True,
    },
    {
        "id": "trap_02",
        "incident_description": (
            "Le service de reporting interne affiche un message d'erreur générique après une mise à jour "
            "planifiée de routine, sans trace d'activité réseau suspecte ni d'accès non autorisé."
        ),
        "expected_cve_ids": [],
        "expected_severity": "basse",
        "is_trap": True,
    },
    {
        "id": "trap_03",
        "incident_description": (
            "Un développeur a commité par erreur un fichier de configuration local dans un dépôt privé "
            "interne, corrigé dans l'heure ; aucune preuve d'accès externe au dépôt n'a été trouvée."
        ),
        "expected_cve_ids": [],
        "expected_severity": "basse",
        "is_trap": True,
    },
    {
        "id": "trap_04",
        "incident_description": (
            "Le pic de charge CPU observé sur le serveur applicatif hier soir correspond exactement à la "
            "fenêtre du job de sauvegarde nocturne planifié, sans autre anomalie relevée dans les logs."
        ),
        "expected_cve_ids": [],
        "expected_severity": "basse",
        "is_trap": True,
    },
]


def sample_cves(n_target: int) -> list[dict]:
    """Échantillonne des CVE réelles et diverses depuis le corpus Pinecone."""
    seen_ids: set[str] = set()
    sampled: list[dict] = []

    for query in SAMPLING_QUERIES:
        if len(sampled) >= n_target:
            break
        results = lookup_cve(query=query, top_k=3)
        for r in results:
            if r["cve_id"] in seen_ids:
                continue
            if r.get("cvss_severity") not in CVSS_TO_FR_SEVERITY:
                continue  # on ignore les CVE sans sévérité exploitable (UNKNOWN)
            seen_ids.add(r["cve_id"])
            sampled.append(r)
            if len(sampled) >= n_target:
                break

    return sampled


def generate_incident_for_cve(llm: ChatAnthropic, cve: dict) -> str:
    prompt = INCIDENT_GENERATION_PROMPT.format(cve_description=cve["description"])
    response = llm.invoke(prompt)
    return response.content.strip()


def main():
    parser = argparse.ArgumentParser(description="Construit le dataset d'évaluation SecureRAG.")
    parser.add_argument("--n-cases", type=int, default=20, help="Nombre de cas basés sur de vraies CVE à générer.")
    parser.add_argument("--output", type=Path, default=Path("evals/dataset.jsonl"))
    args = parser.parse_args()

    print(f"Échantillonnage de {args.n_cases} CVE réelles depuis le corpus Pinecone...")
    sampled_cves = sample_cves(args.n_cases)
    print(f"{len(sampled_cves)} CVE échantillonnées.")

    llm = ChatAnthropic(model=MODEL_NAME, temperature=0.7)

    dataset = []
    for i, cve in enumerate(sampled_cves, start=1):
        print(f"[{i}/{len(sampled_cves)}] Génération du scénario pour {cve['cve_id']}...")
        incident_description = generate_incident_for_cve(llm, cve)
        dataset.append({
            "id": f"case_{i:02d}",
            "incident_description": incident_description,
            "expected_cve_ids": [cve["cve_id"]],
            "expected_severity": CVSS_TO_FR_SEVERITY[cve["cvss_severity"]],
            "is_trap": False,
            # Champ de traçabilité (pas utilisé par l'évaluation elle-même, utile pour audit manuel)
            "_source_cve_description": cve["description"][:200],
        })

    dataset.extend(TRAP_CASES)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for case in dataset:
            f.write(json.dumps(case, ensure_ascii=False) + "\n")

    print(f"\n{len(dataset)} cas écrits dans {args.output} "
          f"({len(sampled_cves)} basés sur de vraies CVE, {len(TRAP_CASES)} pièges).")
    print("\n⚠️  Vérifie manuellement quelques scénarios générés avant de lancer l'évaluation : "
          "certains pourraient être trop vagues ou trop révélateurs de la CVE source.")


if __name__ == "__main__":
    main()
