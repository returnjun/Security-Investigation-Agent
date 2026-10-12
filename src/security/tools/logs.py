"""安全日志查询工具。"""

from typing import Any

from langchain_core.tools import tool

from security.repository import get_security_logs


@tool
def search_security_log(ip: str, event_id: str | None = None) -> list[dict[str, Any]]:
    """按资产 IPv4 地址查询演示安全日志。"""
    return get_security_logs(ip, event_id=event_id)
