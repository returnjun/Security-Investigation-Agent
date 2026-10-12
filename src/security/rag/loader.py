"""读取仓库中经过人工挑选的安全知识文档。"""

import json
import os
import re
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter


def knowledge_root() -> Path:
    configured = os.getenv("SECURITY_KNOWLEDGE_DIR")
    return (
        Path(configured).expanduser().resolve()
        if configured
        else Path(__file__).resolve().parents[3] / "knowledge"
    )


def load_knowledge() -> list[Document]:
    """按文档标题、知识编号和来源构建可引用的文本块。"""
    root = knowledge_root()
    splitter = RecursiveCharacterTextSplitter(chunk_size=650, chunk_overlap=80)
    chunks: list[Document] = []
    known_ids: set[str] = set()
    for path in sorted(root.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        title = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        identifier = re.search(r"^知识编号：\s*(.+)$", text, re.MULTILINE)
        source = re.search(r"^来源：\s*(https?://\S+)$", text, re.MULTILINE)
        if not title or not identifier or not source:
            continue
        metadata = {
            "id": identifier.group(1).strip(),
            "title": title.group(1).strip(),
            "source_url": source.group(1).strip(),
            "source_path": str(path.relative_to(root)).replace("\\", "/"),
        }
        known_ids.add(metadata["id"])
        for index, part in enumerate(splitter.split_text(text), 1):
            chunks.append(Document(page_content=part, metadata={**metadata, "chunk": index}))
    for path in sorted((root / "mitre").glob("T*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        identifier = f"ATTACK-{data['id']}"
        if identifier in known_ids:
            continue
        content = "\n".join(
            (
                f"# {data['id']} {data['name']}",
                f"战术：{data['tactic']}",
                f"攻击说明：{data['description']}",
                f"检测方法：{data['detection']}",
                f"缓解措施：{data['mitigation']}",
            )
        )
        chunks.append(
            Document(
                page_content=content,
                metadata={
                    "id": identifier,
                    "title": f"{data['id']} · {data['name']}",
                    "source_url": data["source_url"],
                    "source_path": str(path.relative_to(root)).replace("\\", "/"),
                    "chunk": 1,
                },
            )
        )
    return chunks
