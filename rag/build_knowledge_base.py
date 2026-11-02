import os

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_CACHE_DIR = os.path.join(_PROJECT_ROOT, "model_cache", "fastembed")
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS"] = "1"

import chromadb
from fastembed import TextEmbedding

DOCS_ROOT = os.path.join(_PROJECT_ROOT, "rag", "documents")
DB_PATH = os.path.join(_PROJECT_ROOT, "rag", "chroma_db")

def chunk_markdown(text, source_file):
    """Split a markdown doc into chunks by ## section headers."""
    chunks = []
    sections = text.split("\n## ")
    for i, section in enumerate(sections):
        if i == 0:
            header = section.strip()
        else:
            header = "## " + section.strip()
        if header.strip():
            chunks.append(header.strip())
    return chunks

def load_documents():
    all_chunks = []
    all_metadatas = []
    all_ids = []
    chunk_id = 0

    for category in os.listdir(DOCS_ROOT):
        category_path = os.path.join(DOCS_ROOT, category)
        if not os.path.isdir(category_path):
            continue
        for filename in os.listdir(category_path):
            if not filename.endswith(".md"):
                continue
            filepath = os.path.join(category_path, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                text = f.read()

            chunks = chunk_markdown(text, filename)
            for chunk in chunks:
                all_chunks.append(chunk)
                all_metadatas.append({
                    "source_file": filename,
                    "category": category
                })
                all_ids.append(f"chunk_{chunk_id}")
                chunk_id += 1

    return all_chunks, all_metadatas, all_ids

print("Loading documents and chunking...")
chunks, metadatas, ids = load_documents()
print(f"Total chunks created: {len(chunks)}")

print("Loading embedding model (BAAI/bge-small-en-v1.5)...")
model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5", cache_dir=_MODEL_CACHE_DIR)

print("Generating embeddings...")
embeddings = list(model.embed(chunks))
embeddings = [e.tolist() for e in embeddings]

print("Setting up Chroma collection...")
client = chromadb.PersistentClient(path=DB_PATH)
collection = client.get_or_create_collection(name="nids_knowledge_base")

print("Storing chunks in Chroma...")
collection.add(
    ids=ids,
    embeddings=embeddings,
    documents=chunks,
    metadatas=metadatas
)

print(f"\nDone. Stored {len(chunks)} chunks in {DB_PATH}")