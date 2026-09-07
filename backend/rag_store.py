"""ChromaDB-backed RAG store for per-client knowledge base entries.
Uses sentence-transformers all-MiniLM-L6-v2 embeddings (lazy-loaded)."""
import logging
import os
import uuid
from typing import Any

logger = logging.getLogger(__name__)

_STATE: dict[str, Any] = {"client": None, "collection": None, "encoder": None, "ready": False, "error": None}

CHROMA_PATH = os.environ.get("CHROMA_PATH", "/app/backend/.chroma_db")
COLLECTION_NAME = "socpilot_kb"


def _lazy_init() -> bool:
    """Initialise Chroma + encoder on first use. Returns True on success."""
    if _STATE.get("ready"):
        return True
    try:
        import chromadb  # type: ignore
        from sentence_transformers import SentenceTransformer  # type: ignore

        os.makedirs(CHROMA_PATH, exist_ok=True)
        client = chromadb.PersistentClient(path=CHROMA_PATH)
        collection = client.get_or_create_collection(name=COLLECTION_NAME)
        encoder = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
        _STATE.update({"client": client, "collection": collection, "encoder": encoder, "ready": True, "error": None})
        return True
    except Exception as e:
        _STATE["error"] = str(e)
        logger.warning("RAG store init failed: %s", e)
        return False


def add_documents(client_id: str, kb_type: str, source_file: str, docs: list[str]) -> int:
    """Add a batch of text chunks. Returns number added."""
    if not docs:
        return 0
    if not _lazy_init():
        return 0
    encoder = _STATE["encoder"]
    collection = _STATE["collection"]
    ids = [str(uuid.uuid4()) for _ in docs]
    metas = [{"client_id": client_id, "kb_type": kb_type, "source": source_file} for _ in docs]
    try:
        embeddings = encoder.encode(docs, show_progress_bar=False).tolist()
        collection.add(ids=ids, documents=docs, metadatas=metas, embeddings=embeddings)
        return len(docs)
    except Exception as e:
        logger.warning("Chroma add failed: %s", e)
        return 0


def query(client_id: str, text: str, n_results: int = 4) -> list[dict]:
    if not _lazy_init():
        return []
    try:
        encoder = _STATE["encoder"]
        collection = _STATE["collection"]
        emb = encoder.encode([text]).tolist()
        res = collection.query(query_embeddings=emb, n_results=n_results,
                               where={"client_id": client_id})
        matches = []
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        for d, m, dist in zip(docs, metas, dists):
            matches.append({
                "text": d[:500],
                "kb_type": (m or {}).get("kb_type"),
                "source": (m or {}).get("source"),
                "similarity": round(1 - float(dist), 3),
            })
        return matches
    except Exception as e:
        logger.warning("Chroma query failed: %s", e)
        return []


def delete_for_client(client_id: str, source_file: str | None = None) -> int:
    if not _lazy_init():
        return 0
    try:
        collection = _STATE["collection"]
        where = {"client_id": client_id}
        if source_file:
            where = {"$and": [{"client_id": client_id}, {"source": source_file}]}
        collection.delete(where=where)
        return 1
    except Exception as e:
        logger.warning("Chroma delete failed: %s", e)
        return 0


def status() -> dict:
    return {
        "ready": _STATE.get("ready", False),
        "error": _STATE.get("error"),
        "path": CHROMA_PATH,
    }
