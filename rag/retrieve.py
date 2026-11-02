import os

# Use the embedding model bundled with the project instead of the user's
# home cache. These must be set BEFORE fastembed / huggingface_hub
# are imported, because they are read at import time.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_CACHE_DIR = os.path.join(_PROJECT_ROOT, "model_cache", "fastembed")
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS"] = "1"

import chromadb
from fastembed import TextEmbedding

# Absolute path, so it works no matter which folder the app is launched from
DB_PATH = os.path.join(_PROJECT_ROOT, "rag", "chroma_db")

model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5", cache_dir=_MODEL_CACHE_DIR)
client = chromadb.PersistentClient(path=DB_PATH)
collection = client.get_collection(name="nids_knowledge_base")

def retrieve(query, top_k=3):
    query_embedding = list(model.embed([query]))
    query_embedding = [e.tolist() for e in query_embedding]
    results = collection.query(
        query_embeddings=query_embedding,
        n_results=top_k
    )

    retrieved = []
    for i in range(len(results["documents"][0])):
        retrieved.append({
            "text": results["documents"][0][i],
            "source_file": results["metadatas"][0][i]["source_file"],
            "category": results["metadatas"][0][i]["category"],
            "distance": results["distances"][0][i]
        })
    return retrieved

if __name__ == "__main__":
    test_queries = [
        "Port Scan detected, many destination ports contacted",
        "Sudden spike in traffic overwhelming a server",
        "Repeated failed login attempts from same source"
    ]

    for q in test_queries:
        print(f"\n{'='*60}")
        print(f"QUERY: {q}")
        print('='*60)
        results = retrieve(q, top_k=2)
        for r in results:
            print(f"\n[{r['source_file']}] (distance: {r['distance']:.4f})")
            print(r["text"][:200] + "...")