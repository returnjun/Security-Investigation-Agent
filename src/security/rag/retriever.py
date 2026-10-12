"""Chroma 向量检索、关键词重排和不可用时的回退检索。"""

import hashlib
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings

from core import settings
from security.rag.loader import load_knowledge

logger = logging.getLogger(__name__)
_INDEX_LOCK = threading.Lock()


def vector_directory() -> Path:
    configured = os.getenv("SECURITY_VECTOR_DB_PATH")
    return (
        Path(configured).expanduser().resolve()
        if configured
        else Path(__file__).resolve().parents[3] / ".runtime-tools" / "security_chroma"
    )


def _tokens(text: str) -> set[str]:
    lowered = text.lower()
    latin = set(re.findall(r"[a-z][a-z0-9._-]{1,}|cve-\d{4}-\d{4,}", lowered))
    chinese = re.findall(r"[\u4e00-\u9fff]+", lowered)
    pairs = {word[index : index + 2] for word in chinese for index in range(len(word) - 1)}
    return latin | pairs


def _relevance(query: str, document: Document) -> int:
    identifier = document.metadata["id"].lower()
    if identifier in query.lower():
        return 100
    return len(_tokens(query) & _tokens(document.page_content + " " + document.metadata["title"]))


def _rank(query: str, documents: list[Document]) -> list[Document]:
    cve = re.search(r"CVE-\d{4}-\d{4,}", query, re.IGNORECASE)
    if cve:
        documents = [doc for doc in documents if doc.metadata["id"].lower() == cve.group().lower()]
    else:
        # 普通主机调查不能被无关的 CVE 文档误导。
        documents = [doc for doc in documents if not doc.metadata["id"].startswith("CVE-")]
        techniques = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", query, re.IGNORECASE))
        if techniques:
            documents = [
                doc
                for doc in documents
                if not doc.metadata["id"].startswith("ATTACK-")
                or any(doc.metadata["id"].upper().endswith(item.upper()) for item in techniques)
            ]
    ranked = sorted(documents, key=lambda doc: _relevance(query, doc), reverse=True)
    result: list[Document] = []
    seen: set[str] = set()
    for doc in ranked:
        identifier = doc.metadata["id"]
        if identifier not in seen and _relevance(query, doc) > 0:
            result.append(doc)
            seen.add(identifier)
        if len(result) == 3:
            break
    return result


def _vector_candidates(query: str, documents: list[Document]) -> list[Document]:
    if not settings.AIGCBEST_API_KEY:
        raise RuntimeError("未配置嵌入模型密钥")
    digest = hashlib.sha256()
    digest.update(settings.AIGCBEST_EMBEDDING_MODEL.encode())
    for document in documents:
        digest.update(document.page_content.encode())
    collection = f"security_{digest.hexdigest()[:16]}"
    directory = vector_directory()
    directory.mkdir(parents=True, exist_ok=True)
    embeddings = OpenAIEmbeddings(
        model=settings.AIGCBEST_EMBEDDING_MODEL,
        base_url=f"{settings.AIGCBEST_BASE_URL.rstrip('/')}/v1",
        api_key=settings.AIGCBEST_API_KEY,
        request_timeout=20,
        max_retries=1,
    )
    with _INDEX_LOCK:
        store = Chroma(
            collection_name=collection,
            persist_directory=str(directory),
            embedding_function=embeddings,
        )
        ids = [f"{doc.metadata['id']}-{doc.metadata['chunk']}" for doc in documents]
        existing = set(store.get(ids=ids, include=[])["ids"])
        missing = [
            (identifier, doc)
            for identifier, doc in zip(ids, documents, strict=True)
            if identifier not in existing
        ]
        if missing:
            store.add_documents(
                [doc for _, doc in missing], ids=[identifier for identifier, _ in missing]
            )
    return store.similarity_search(query, k=min(8, len(documents)))


def search_security_knowledge(query: str) -> tuple[list[dict[str, Any]], str]:
    """优先向量召回，再用可解释的词项重排；失败时退回本地检索。"""
    documents = load_knowledge()
    if not documents:
        return [], "知识库为空"
    if re.search(r"CVE-\d{4}-\d{4,}", query, re.IGNORECASE):
        ranked = _rank(query, documents)
        return [
            {
                "id": doc.metadata["id"],
                "title": doc.metadata["title"],
                "content": doc.page_content,
                "source_url": doc.metadata["source_url"],
                "source_path": doc.metadata["source_path"],
                "score": _relevance(query, doc),
            }
            for doc in ranked
        ], "CVE 精确检索"
    mode = os.getenv("SECURITY_RAG_MODE", "auto").lower()
    if mode not in {"auto", "vector", "lexical"}:
        mode = "auto"
    candidates = documents
    retrieval_mode = "本地关键词检索"
    if mode != "lexical":
        try:
            candidates = _vector_candidates(query, documents)
            retrieval_mode = "向量召回与关键词重排"
        except Exception as exc:
            logger.warning("安全知识向量检索不可用，使用本地检索：%s", type(exc).__name__)
            if mode == "vector":
                return [], "向量检索不可用"
            retrieval_mode = "本地关键词回退"
    ranked = _rank(query, candidates)
    if not ranked and candidates is not documents and mode == "auto":
        ranked = _rank(query, documents)
        retrieval_mode = "本地关键词回退"
    return [
        {
            "id": doc.metadata["id"],
            "title": doc.metadata["title"],
            "content": doc.page_content,
            "source_url": doc.metadata["source_url"],
            "source_path": doc.metadata["source_path"],
            "score": _relevance(query, doc),
        }
        for doc in ranked
    ], retrieval_mode
