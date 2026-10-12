"""将 LangGraph 节点更新转为可回放、不会泄露模型原始提示词的轨迹。"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from security.state import SecurityState

EVENT_TYPES = {
    "siem_collector": "采集",
    "alert_detector": "检测",
    "intent_analyzer": "识别",
    "planner_agent": "规划",
    "executor": "路由",
    "asset_agent": "查询",
    "history_agent": "历史",
    "log_agent": "查询",
    "vulnerability_agent": "查询",
    "threat_agent": "查询",
    "rag_agent": "检索",
    "evidence_collector": "汇总",
    "mitre_mapper": "映射",
    "risk_agent": "评估",
    "report_agent": "报告",
    "response_planner": "响应建议",
    "human_approval": "审批",
    "response_tool": "模拟执行",
}


def trace_input(node: str, state: SecurityState) -> dict[str, Any]:
    """只记录调查上下文，不记录密钥、完整模型提示或知识全文。"""
    result: dict[str, Any] = {"asset_ip": state.get("asset_ip")}
    if node == "intent_analyzer":
        result["query"] = state.get("query", "")[:1000]
    elif node == "planner_agent":
        result.update(query=state.get("query", "")[:1000], alert_type=state.get("alert_type"))
    elif node == "executor":
        result.update(
            plan=state.get("investigation_plan", []), completed=state.get("completed_tasks", [])
        )
    elif node in {"log_agent", "asset_agent", "vulnerability_agent"}:
        result["event_id"] = state.get("trigger_event_id")
    elif node == "threat_agent":
        result["source_ips"] = sorted({item["source_ip"] for item in state.get("logs", [])})
    elif node == "rag_agent":
        result["cve_id"] = state.get("cve_id")
    else:
        result["evidence_ids"] = [item["id"] for item in state.get("evidence", [])]
    return result


def trace_output(node: str, values: dict[str, Any]) -> dict[str, Any]:
    """输出面向排障的摘要，原始证据仍在调查结果中单独查看。"""
    if node in {"siem_collector", "alert_detector"}:
        return values
    if node == "intent_analyzer":
        return {key: values.get(key) for key in ("asset_ip", "cve_id", "intent_error")}
    if node == "planner_agent":
        return {
            key: values.get(key) for key in ("investigation_plan", "planner_mode", "plan_reason")
        }
    if node == "executor":
        return {"current_task": values.get("current_task")}
    if node in {
        "asset_agent",
        "history_agent",
        "log_agent",
        "vulnerability_agent",
        "threat_agent",
        "rag_agent",
    }:
        output: dict[str, Any] = {
            "evidence_ids": [item["id"] for item in values.get("task_evidence", [])]
        }
        for key in ("history", "logs", "vulnerabilities", "threat_info", "knowledge"):
            if key in values:
                output["record_count"] = len(values[key])
                break
        if node == "asset_agent":
            output["asset_found"] = bool(values.get("asset_info"))
        if node == "log_agent":
            output["events"] = [
                {"type": item["event"], "count": item["event_count"]}
                for item in values.get("logs", [])
            ]
        if node == "rag_agent":
            output["retrieval_mode"] = values.get("retrieval_mode")
        return output
    if node == "evidence_collector":
        return {
            "plan": values.get("investigation_plan", []),
            "completed": values.get("completed_tasks", []),
            "evidence_ids": [item["id"] for item in values.get("evidence", [])],
        }
    if node == "mitre_mapper":
        return {"technique_ids": [item["id"] for item in values.get("mitre_matches", [])]}
    if node == "risk_agent":
        return {
            "risk_level": values.get("risk_level"),
            "risk_score": values.get("risk_score"),
            "findings": [item["title"] for item in values.get("findings", [])],
        }
    return {
        "report_ready": bool(values.get("report")),
        "report_length": len(values.get("report", "")),
    }


def make_trace_entry(
    investigation_id: str,
    sequence: int,
    node: str,
    input_summary: dict[str, Any],
    values: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid4()),
        "investigation_id": investigation_id,
        "sequence": sequence,
        "node_name": node,
        "event_type": EVENT_TYPES[node],
        "input": input_summary,
        "output": trace_output(node, values),
        "created_at": datetime.now(UTC).isoformat(),
    }
