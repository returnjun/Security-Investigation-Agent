"""来源 IP 信誉查询工具。"""

from typing import Any

from langchain_core.tools import tool

from security.repository import get_ip_reputation


@tool
def check_ip_reputation(ip: str) -> dict[str, Any]:
    """查询演示情报库中某个来源 IPv4 地址的信誉。"""
    return get_ip_reputation(ip)
