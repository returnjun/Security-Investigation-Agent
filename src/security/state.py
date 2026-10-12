"""调查节点共享的 LangGraph 状态。"""

from typing import Any

from langgraph.graph import MessagesState


class SecurityState(MessagesState, total=False):
    query: str
    asset_ip: str | None
    cve_id: str | None
    trigger_event_id: str | None
    trigger_alert_id: str | None
    alert_type: str | None
    intent_error: str | None
    plan: list[str]
    investigation_plan: list[str]
    current_task: str | None
    completed_tasks: list[str]
    planner_mode: str
    plan_reason: str
    execution_trace: list[str]
    evidence: list[dict[str, Any]]
    task_evidence: list[dict[str, Any]]
    asset_info: dict[str, Any]
    logs: list[dict[str, Any]]
    log_scope_note: str | None
    vulnerabilities: list[dict[str, Any]]
    threat_info: list[dict[str, Any]]
    history: list[dict[str, Any]]
    knowledge: list[dict[str, Any]]
    retrieval_mode: str
    attack_mappings: dict[str, dict[str, Any]]
    mitre_matches: list[dict[str, Any]]
    risk_level: str
    risk_score: int
    findings: list[dict[str, Any]]
    recommendations: list[str]
    analysis: str
    report: str
