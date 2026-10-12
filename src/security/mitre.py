"""按明确的日志特征关联 MITRE ATT&CK 技术。"""

import json
from pathlib import Path
from typing import Any

from security.rag.loader import knowledge_root
from security.repository import get_security_policy
from security.state import SecurityState


def _technique(technique_id: str) -> dict[str, Any] | None:
    path: Path = knowledge_root() / "mitre" / f"{technique_id}.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("id") != technique_id:
        return None
    return {key: data[key] for key in ("id", "name", "tactic", "source_url")}


def map_mitre(state: SecurityState) -> SecurityState:
    """技术映射只表示行为匹配，不判断攻击者身份或入侵成功。"""
    logs = state.get("logs", [])
    matches: dict[str, dict[str, Any]] = {}
    if (
        sum(item["event_count"] for item in logs if item["event"] == "SSH 登录失败")
        >= get_security_policy()["ssh_failed_threshold"]
    ):
        technique = _technique("T1110")
        if technique:
            matches["ssh_brute_force"] = technique
    if any(
        item["event"] == "命令解释器执行"
        and item.get("raw_data", {}).get("interpreter") in {"bash", "sh", "powershell", "cmd"}
        for item in logs
    ):
        technique = _technique("T1059")
        if technique:
            matches["command_execution"] = technique
    if any(
        item["event"] == "异常提权" and item.get("raw_data", {}).get("method") == "sudo"
        for item in logs
    ):
        technique = _technique("T1548")
        if technique:
            matches["privilege_escalation"] = technique
    unique = {item["id"]: item for item in matches.values()}
    return {"attack_mappings": matches, "mitre_matches": list(unique.values())}
