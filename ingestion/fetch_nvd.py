"""
Script d'ingestion des CVE depuis l'API NVD (National Vulnerability Database).

Fonctionnalités :
- Pagination automatique sur l'API NVD 2.0
- Gestion du rate limiting (5 req/30s sans clé, 50 req/30s avec clé)
- Idempotence : les CVE déjà téléchargées ne sont pas re-téléchargées
- Sauvegarde brute en JSONL dans data/raw/ pour traçabilité
- Logging structuré des lots traités

Usage :
    python -m ingestion.fetch_nvd --last-mod-days 120 --output data/raw/cves.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 200  # max autorisé par l'API NVD

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("nvd_ingestion")


@dataclass
class NvdClientConfig:
    api_key: str | None
    base_url: str = NVD_BASE_URL
    results_per_page: int = RESULTS_PER_PAGE

    @property
    def sleep_between_requests(self) -> float:
        # Avec clé API : 50 requêtes / 30s -> ~0.6s de marge par requête
        # Sans clé API : 5 requêtes / 30s -> 6s de marge par requête
        return 0.7 if self.api_key else 6.5


def load_already_ingested_ids(output_path: Path) -> set[str]:
    """Relit le fichier de sortie existant pour ne pas re-télécharger les CVE déjà présentes."""
    if not output_path.exists():
        return set()

    ids: set[str] = set()
    with output_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                cve_id = record.get("cve", {}).get("id")
                if cve_id:
                    ids.add(cve_id)
            except json.JSONDecodeError:
                logger.warning("Ligne mal formée ignorée dans %s", output_path)
    logger.info("%d CVE déjà présentes localement, elles seront ignorées.", len(ids))
    return ids


def fetch_page(
    client: httpx.Client,
    config: NvdClientConfig,
    start_index: int,
    last_mod_start: str | None,
    last_mod_end: str | None,
) -> dict:
    """Appelle l'API NVD pour une page de résultats, avec retry basique sur les erreurs transitoires."""
    params: dict[str, str | int] = {
        "resultsPerPage": config.results_per_page,
        "startIndex": start_index,
    }
    if last_mod_start and last_mod_end:
        params["lastModStartDate"] = last_mod_start
        params["lastModEndDate"] = last_mod_end

    headers = {"apiKey": config.api_key} if config.api_key else {}

    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            response = client.get(config.base_url, params=params, headers=headers, timeout=30.0)
            if response.status_code == 429:
                wait = 10 * attempt
                logger.warning("Rate limit atteint (429). Attente de %ds avant retry.", wait)
                time.sleep(wait)
                continue
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            logger.error("Erreur HTTP %s sur startIndex=%d (tentative %d/%d): %s",
                         exc.response.status_code, start_index, attempt, max_retries, exc)
        except httpx.RequestError as exc:
            logger.error("Erreur réseau sur startIndex=%d (tentative %d/%d): %s",
                         start_index, attempt, max_retries, exc)
        time.sleep(3 * attempt)

    raise RuntimeError(f"Échec définitif de récupération pour startIndex={start_index} après {max_retries} tentatives.")


def ingest(
    output_path: Path,
    last_mod_days: int | None,
    max_results: int | None,
) -> None:
    api_key = os.getenv("NVD_API_KEY") or None
    if not api_key:
        logger.warning(
            "Aucune NVD_API_KEY trouvée dans l'environnement. "
            "L'ingestion fonctionnera mais sera fortement limitée en débit (5 req/30s)."
        )

    config = NvdClientConfig(api_key=api_key)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    already_ingested = load_already_ingested_ids(output_path)

    last_mod_start = last_mod_end = None
    if last_mod_days:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=last_mod_days)
        last_mod_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        last_mod_end = end.strftime("%Y-%m-%dT%H:%M:%S.000")
        logger.info("Filtrage sur les CVE modifiées entre %s et %s", last_mod_start, last_mod_end)

    total_written = 0
    start_index = 0
    total_results: int | None = None

    with httpx.Client() as client, output_path.open("a", encoding="utf-8") as out_file:
        while True:
            if total_results is not None and start_index >= total_results:
                break
            if max_results is not None and total_written >= max_results:
                logger.info("Limite max_results=%d atteinte, arrêt.", max_results)
                break

            logger.info("Récupération du lot startIndex=%d...", start_index)
            page = fetch_page(client, config, start_index, last_mod_start, last_mod_end)

            total_results = page.get("totalResults", 0)
            vulnerabilities = page.get("vulnerabilities", [])

            new_in_batch = 0
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve", {}).get("id")
                if not cve_id:
                    continue
                if cve_id in already_ingested:
                    continue
                out_file.write(json.dumps(vuln, ensure_ascii=False) + "\n")
                already_ingested.add(cve_id)
                new_in_batch += 1
                total_written += 1

            out_file.flush()
            logger.info(
                "Lot traité : %d CVE reçues, %d nouvelles écrites (total écrit: %d / %s résultats dispo).",
                len(vulnerabilities), new_in_batch, total_written, total_results,
            )

            start_index += config.results_per_page
            time.sleep(config.sleep_between_requests)

    logger.info("Ingestion terminée. %d nouvelles CVE écrites dans %s", total_written, output_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingestion des CVE depuis l'API NVD.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/cves.jsonl"),
        help="Chemin du fichier JSONL de sortie (append, idempotent).",
    )
    parser.add_argument(
        "--last-mod-days",
        type=int,
        default=None,
        help="Ne récupérer que les CVE modifiées dans les N derniers jours (recommandé pour un premier run rapide).",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=None,
        help="Nombre maximum de nouvelles CVE à écrire (utile pour un test rapide, ex: 200).",
    )
    args = parser.parse_args()

    ingest(output_path=args.output, last_mod_days=args.last_mod_days, max_results=args.max_results)


if __name__ == "__main__":
    main()
