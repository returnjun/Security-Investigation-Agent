"""资产信息查询工具。"""

from typing import Any

from langchain_core.tools import tool

from security.repository import get_asset


@tool
def query_asset(ip: str) -> dict[str, Any]:
    """根据 IPv4 地址查询演示企业资产库。"""
    return get_asset(ip)
