"""
Test rapide de recherche sémantique dans l'index Pinecone, pour vérifier que
la vectorisation fonctionne bien avant de brancher l'agent dessus.

Usage :
    python -m ingestion.test_search "Apache Struts vulnerability"
"""

import os
import sys

from dotenv import load_dotenv

load_dotenv()

MODEL_NAME = "BAAI/bge-base-en-v1.5"
# Instruction recommandée par BAAI pour les requêtes (asymétrique query/passage)
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "


def main():
    if len(sys.argv) < 2:
        print('Usage : python -m ingestion.test_search "ta requête ici"')
        sys.exit(1)

    query = sys.argv[1]

    from pinecone import Pinecone
    from sentence_transformers import SentenceTransformer

    pinecone_api_key = os.getenv("PINECONE_API_KEY")
    index_name = os.getenv("PINECONE_INDEX_NAME", "securerag-cve")

    print(f"Chargement du modèle '{MODEL_NAME}'...")
    model = SentenceTransformer(MODEL_NAME, device="cpu")

    pc = Pinecone(api_key=pinecone_api_key)
    index = pc.Index(index_name)

    query_embedding = model.encode(
        QUERY_INSTRUCTION + query,
        normalize_embeddings=True,
    ).tolist()

    results = index.query(vector=query_embedding, top_k=5, include_metadata=True)

    print(f"\nTop 5 résultats pour : \"{query}\"\n" + "-" * 60)
    for match in results["matches"]:
        meta = match["metadata"]
        print(f"[{match['score']:.3f}] {meta['cve_id']} (sévérité: {meta['cvss_severity']})")
        print(f"    {meta['text'][:200]}...")
        print()


if __name__ == "__main__":
    main()
