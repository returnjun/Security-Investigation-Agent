"""安全知识检索工具。"""

from typing import Any

from langchain_core.tools import tool

from security.rag import search_security_knowledge


@tool
def security_rag_search(query: str) -> dict[str, Any]:
    """检索带来源的 CVE、攻击技术与事件响应知识。"""
    matches, mode = search_security_knowledge(query)
    return {"matches": matches, "mode": mode}
