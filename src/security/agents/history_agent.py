"""资产历史调查节点。"""

from security.repository import get_asset_history
from security.state import SecurityState


def history_agent(state: SecurityState) -> SecurityState:
    ip = state.get("asset_ip")
    history = get_asset_history(ip, days=7) if ip else []
    evidence = [
        {
            "id": f"HIST-{item['investigation_id']}",
            "kind": "历史调查",
            "summary": (
                f"{item['created_at']}，风险{item['risk_level']}，评分{item['risk_score']}，"
                f"人工反馈{','.join(item['feedback_labels']) or '暂无'}"
            ),
        }
        for item in history
    ]
    return {"history": history, "task_evidence": evidence}
