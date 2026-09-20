"""
Script de vectorisation et d'indexation des CVE dans Pinecone.

Étapes :
1. Lecture des CVE brutes (data/raw/cves.jsonl, produites par fetch_nvd.py)
2. Chunking : transformation de chaque CVE en un texte structuré prêt à être vectorisé
3. Embeddings : génération des vecteurs via BAAI/bge-base-en-v1.5 (local, CPU, gratuit)
4. Indexation : upsert idempotent dans Pinecone (l'ID du vecteur = l'ID de la CVE,
   donc relancer le script met à jour plutôt que dupliquer)

Usage :
    python -m ingestion.build_vectorstore
    python -m ingestion.build_vectorstore --input data/raw/cves.jsonl --batch-size 32
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("build_vectorstore")

load_dotenv()

MODEL_NAME = "BAAI/bge-base-en-v1.5"
EMBEDDING_DIM = 768  # dimension native de bge-base-en-v1.5
PINECONE_METRIC = "cosine"


def load_cves(path: Path) -> list[dict[str, Any]]:
    """Charge les CVE depuis le fichier JSONL produit par fetch_nvd.py."""
    if not path.exists():
        logger.error(f"Fichier introuvable : {path}. Lance d'abord fetch_nvd.py.")
        sys.exit(1)

    cves = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                cves.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"Ligne {line_num} ignorée (JSON invalide) : {e}")

    logger.info(f"{len(cves)} CVE chargées depuis {path}")
    return cves


def extract_cve_fields(cve_raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Extrait les champs utiles d'un enregistrement CVE au format NVD API 2.0.
    Retourne None si la CVE est mal formée (pas assez d'infos exploitables).
    """
    try:
        cve = cve_raw.get("cve", cve_raw)  # tolère un objet déjà "déballé"
        cve_id = cve["id"]

        # Description (en anglais en priorité)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        if not description:
            logger.warning(f"{cve_id} ignorée : pas de description exploitable")
            return None

        # Score CVSS (on prend la version la plus récente disponible : v3.1 > v3.0 > v2)
        cvss_score = None
        cvss_severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                metric_data = metrics[key][0]
                cvss_data = metric_data.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = metric_data.get(
                    "baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN")
                )
                break

        # CWE (type de faiblesse)
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])

        # Produits/versions affectés (on limite pour ne pas surcharger le texte)
        affected_products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        affected_products.append(criteria)
        affected_products = affected_products[:10]  # cap raisonnable

        published = cve.get("published", "")

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cwe_ids": cwe_ids,
            "affected_products": affected_products,
            "published": published,
        }

    except (KeyError, IndexError, TypeError) as e:
        logger.warning(f"CVE mal formée ignorée : {e}")
        return None


def build_chunk_text(fields: dict[str, Any]) -> str:
    """
    Construit le texte structuré qui sera vectorisé.
    Le format vise à donner un maximum de signal sémantique utile pour le
    retrieval (produit + description + sévérité), sans bruit inutile.
    """
    parts = [f"CVE {fields['cve_id']}."]

    if fields["affected_products"]:
        # On extrait juste vendor/produit depuis le CPE pour rester lisible,
        # ex: cpe:2.3:a:apache:struts:2.5.30:* -> "apache struts 2.5.30"
        readable_products = []
        for cpe in fields["affected_products"][:5]:
            segments = cpe.split(":")
            if len(segments) >= 5:
                vendor, product, version = segments[3], segments[4], segments[5]
                readable_products.append(f"{vendor} {product} {version}".strip())
        if readable_products:
            parts.append(f"Produits affectés : {', '.join(readable_products)}.")

    parts.append(fields["description"])

    if fields["cvss_score"] is not None:
        parts.append(
            f"Score CVSS : {fields['cvss_score']} (sévérité {fields['cvss_severity']})."
        )

    if fields["cwe_ids"]:
        parts.append(f"Type de faiblesse : {', '.join(fields['cwe_ids'])}.")

    return " ".join(parts)


def build_metadata(fields: dict[str, Any], chunk_text: str) -> dict[str, Any]:
    """
    Métadonnées stockées à côté du vecteur dans Pinecone, pour permettre
    le filtrage (par sévérité, date...) et pour retrouver le texte source
    sans requête supplémentaire.
    """
    return {
        "cve_id": fields["cve_id"],
        "cvss_score": fields["cvss_score"] if fields["cvss_score"] is not None else -1.0,
        "cvss_severity": fields["cvss_severity"],
        "cwe_ids": fields["cwe_ids"][:5],  # Pinecone limite la taille des métadonnées
        "published": fields["published"],
        "text": chunk_text[:2000],  # cap pour rester sous les limites de métadonnées Pinecone
    }


def get_or_create_index(pc, index_name: str):
    """Récupère l'index Pinecone, le crée s'il n'existe pas encore (idempotent)."""
    from pinecone import ServerlessSpec

    existing = [idx["name"] for idx in pc.list_indexes()]
    if index_name in existing:
        logger.info(f"Index Pinecone '{index_name}' déjà existant, réutilisation.")
    else:
        logger.info(f"Création de l'index Pinecone '{index_name}' (dim={EMBEDDING_DIM})...")
        pc.create_index(
            name=index_name,
            dimension=EMBEDDING_DIM,
            metric=PINECONE_METRIC,
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )
        # L'index met quelques secondes à devenir "ready" après création
        while not pc.describe_index(index_name).status["ready"]:
            time.sleep(1)
        logger.info("Index prêt.")

    return pc.Index(index_name)


def main():
    parser = argparse.ArgumentParser(description="Vectorise et indexe les CVE dans Pinecone.")
    parser.add_argument("--input", default="data/raw/cves.jsonl", help="Fichier JSONL des CVE brutes")
    parser.add_argument("--batch-size", type=int, default=32, help="Taille des batches d'embedding/upsert")
    args = parser.parse_args()

    pinecone_api_key = os.getenv("PINECONE_API_KEY")
    index_name = os.getenv("PINECONE_INDEX_NAME", "securerag-cve")

    if not pinecone_api_key:
        logger.error("PINECONE_API_KEY manquante dans .env")
        sys.exit(1)

    # --- 1. Chargement et chunking ---
    raw_cves = load_cves(Path(args.input))

    chunks = []
    skipped = 0
    for raw in raw_cves:
        fields = extract_cve_fields(raw)
        if fields is None:
            skipped += 1
            continue
        text = build_chunk_text(fields)
        metadata = build_metadata(fields, text)
        chunks.append({"id": fields["cve_id"], "text": text, "metadata": metadata})

    logger.info(f"{len(chunks)} CVE prêtes à être vectorisées ({skipped} ignorées).")

    if not chunks:
        logger.warning("Aucune CVE à indexer, arrêt.")
        return

    # --- 2. Chargement du modèle d'embedding ---
    logger.info(f"Chargement du modèle d'embedding '{MODEL_NAME}' (peut prendre 1-2 min la première fois)...")
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(MODEL_NAME, device="cpu")

    # --- 3. Connexion Pinecone ---
    from pinecone import Pinecone

    pc = Pinecone(api_key=pinecone_api_key)
    index = get_or_create_index(pc, index_name)

    # --- 4. Embedding + upsert par batches ---
    batch_size = args.batch_size
    total = len(chunks)
    indexed = 0

    for i in range(0, total, batch_size):
        batch = chunks[i : i + batch_size]
        texts = [c["text"] for c in batch]

        embeddings = model.encode(
            texts,
            normalize_embeddings=True,  # requis pour une similarité cosinus correcte
            show_progress_bar=False,
        )

        vectors = [
            {"id": c["id"], "values": emb.tolist(), "metadata": c["metadata"]}
            for c, emb in zip(batch, embeddings)
        ]

        try:
            index.upsert(vectors=vectors)
            indexed += len(vectors)
            logger.info(f"Batch {i // batch_size + 1} : {indexed}/{total} CVE indexées.")
        except Exception as e:
            logger.error(f"Échec de l'upsert du batch {i // batch_size + 1} : {e}")

    logger.info(f"Terminé. {indexed}/{total} CVE indexées dans Pinecone (index '{index_name}').")


if __name__ == "__main__":
    main()
