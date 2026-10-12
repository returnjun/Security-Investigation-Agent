"""根据已有规则发现生成受限的响应建议，不让模型直接操作环境。"""

from typing import Any

from security.repository import get_security_policy


def plan_response(result: dict[str, Any]) -> list[dict[str, str]]:
    if result["risk_level"] not in {"中", "高"}:
        return []
    policy = get_security_policy()
    actions = (
        [
            {
                "type": "create_ticket",
                "target": result["id"],
                "reason": "记录本次调查与人工复核任务",
                "simulation": "只生成演示工单编号",
            }
        ]
        if policy["simulate_ticket"]
        else []
    )
    brute_force = any(item["title"] == "疑似 SSH 暴力破解" for item in result["findings"])
    for item in result.get("threat_info", []):
        if (
            policy["simulate_block_ip"]
            and brute_force
            and item.get("classification") == "可疑"
            and item.get("score", 0) >= 70
        ):
            actions.append(
                {
                    "type": "block_ip",
                    "target": item["ip"],
                    "reason": "大量失败登录且演示信誉标记可疑，建议人工确认来源后处置",
                    "simulation": "仅记录封禁模拟结果，不修改防火墙",
                }
            )
    return actions
