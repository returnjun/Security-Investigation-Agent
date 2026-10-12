"""安全调查的结构化 API 与步骤流。"""

import json
import os
from collections.abc import AsyncGenerator
from ipaddress import IPv4Address
from typing import Annotated, Any, Literal
from urllib.parse import urlencode
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse, StreamingResponse
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field, field_validator

from core import settings
from schema.models import AllModelEnum
from security.auth import current_user, require_admin, require_manager
from security.repository import (
    get_agent_trace,
    get_alert_for_event,
    get_asset_history,
    get_feedback,
    get_investigation,
    get_response_plan,
    get_security_policy,
    link_alert_investigation,
    list_demo_assets,
    list_siem_alerts,
    list_siem_events,
    recent_investigations,
    save_asset_history,
    save_feedback,
    save_investigation,
    update_security_policy,
)
from security.response.approval import queue_response, resolve_response
from security.siem.collector import collect
from security.siem.event_generator import generate_event
from security.siem.schema import EventType, SecurityEvent
from security.state import SecurityState
from security.trace import make_trace_entry, trace_input
from security.workflow import security_investigation_agent

router = APIRouter(prefix="/security", tags=["安全事件调查"], dependencies=[Depends(current_user)])
trace_page_router = APIRouter(tags=["安全事件调查"], dependencies=[Depends(current_user)])


def ensure_model_available(model: AllModelEnum) -> None:
    if model not in settings.AVAILABLE_MODELS:
        raise HTTPException(status_code=400, detail=f"模型 {model.value} 不可用")

STEP_LABELS = {
    "intent_analyzer": "识别调查目标",
    "planner_agent": "生成调查计划",
    "executor": "选择下一项任务",
    "asset_agent": "查询资产信息",
    "history_agent": "读取资产调查历史",
    "log_agent": "分析安全日志",
    "vulnerability_agent": "查询漏洞信息",
    "threat_agent": "核验来源 IP 信誉",
    "rag_agent": "检索安全知识",
    "evidence_collector": "汇总证据并判断下一步",
    "mitre_mapper": "映射 MITRE ATT&CK 技术",
    "risk_agent": "计算规则风险",
    "report_agent": "生成调查报告",
}


class InvestigationRequest(BaseModel):
    query: str = Field(min_length=3, max_length=1000, description="IP 调查或安全知识问题")
    model: AllModelEnum | None = Field(default=None, description="用于规划与生成摘要的模型")

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("调查问题不能为空")
        return value


class InvestigationResponse(BaseModel):
    id: str
    query: str
    asset_ip: str | None
    asset_info: dict[str, Any]
    logs: list[dict[str, Any]]
    vulnerabilities: list[dict[str, Any]]
    threat_info: list[dict[str, Any]]
    history: list[dict[str, Any]] = Field(default_factory=list)
    risk_level: str
    risk_score: int
    findings: list[dict[str, Any]]
    recommendations: list[str]
    analysis: str
    report: str
    cve_id: str | None = None
    trigger_event_id: str | None = None
    trigger_alert_id: str | None = None
    investigation_plan: list[str] = Field(default_factory=list)
    completed_tasks: list[str] = Field(default_factory=list)
    planner_mode: str = ""
    plan_reason: str = ""
    execution_trace: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    knowledge: list[dict[str, Any]] = Field(default_factory=list)
    mitre_matches: list[dict[str, Any]] = Field(default_factory=list)
    trace: list[dict[str, Any]] = Field(default_factory=list)
    response_plan: dict[str, Any] | None = None
    retrieval_mode: str = ""
    log_scope_note: str | None = None
    data_source: str = "本地合成演示数据与带来源的知识文档"


class SimulationRequest(BaseModel):
    scenario: EventType = "SSH_FAILED_LOGIN"
    asset_ip: IPv4Address = IPv4Address("192.168.1.10")
    model: AllModelEnum | None = None


class SiemIntakeResponse(BaseModel):
    event: SecurityEvent
    alert: dict[str, Any] | None
    investigation: InvestigationResponse | None
    created: bool


class FeedbackRequest(BaseModel):
    investigation_id: str
    label: Literal["correct", "false_positive", "needs_revision", "wrong"]
    comment: str = Field(default="", max_length=1000)


class ApprovalRequest(BaseModel):
    approved: bool


class PolicyUpdate(BaseModel):
    ssh_failed_threshold: int | None = Field(default=None, ge=20, le=10000)
    port_scan_threshold: int | None = Field(default=None, ge=5, le=10000)
    simulate_block_ip: bool | None = None
    simulate_ticket: bool | None = None


def _build_result(investigation_id: str, state: SecurityState) -> InvestigationResponse:
    return InvestigationResponse(
        id=investigation_id,
        query=state["query"],
        asset_ip=state.get("asset_ip"),
        asset_info=state.get("asset_info", {}),
        logs=state.get("logs", []),
        vulnerabilities=state.get("vulnerabilities", []),
        threat_info=state.get("threat_info", []),
        history=state.get("history", []),
        risk_level=state["risk_level"],
        risk_score=state["risk_score"],
        findings=state["findings"],
        recommendations=state["recommendations"],
        analysis=state["analysis"],
        report=state["report"],
        cve_id=state.get("cve_id"),
        trigger_event_id=state.get("trigger_event_id"),
        trigger_alert_id=state.get("trigger_alert_id"),
        investigation_plan=state.get("investigation_plan", []),
        completed_tasks=state.get("completed_tasks", []),
        planner_mode=state.get("planner_mode", ""),
        plan_reason=state.get("plan_reason", ""),
        execution_trace=state.get("execution_trace", []),
        evidence=state.get("evidence", []),
        knowledge=state.get("knowledge", []),
        mitre_matches=state.get("mitre_matches", []),
        retrieval_mode=state.get("retrieval_mode", ""),
        log_scope_note=state.get("log_scope_note"),
    )


def _run_config(request: InvestigationRequest) -> RunnableConfig:
    model = request.model or settings.DEFAULT_MODEL
    ensure_model_available(model)
    return RunnableConfig(configurable={"thread_id": str(uuid4()), "model": model})


def _initial_state(request: InvestigationRequest) -> SecurityState:
    return {"query": request.query, "messages": [HumanMessage(content=request.query)]}


async def _walk_investigation(
    state: SecurityState, config: RunnableConfig, investigation_id: str, start_sequence: int = 0
) -> AsyncGenerator[tuple[str, dict[str, Any]], None]:
    sequence = start_sequence
    async for update in security_investigation_agent.astream(
        state, config=config, stream_mode="updates"
    ):
        for node, values in update.items():
            if not isinstance(values, dict):
                continue
            sequence += 1
            before = trace_input(node, state)
            state.update(values)
            yield node, make_trace_entry(investigation_id, sequence, node, before, values)


async def _complete_investigation(
    request: InvestigationRequest,
    initial_state: SecurityState | None = None,
    siem_context: tuple[SecurityEvent, dict[str, Any]] | None = None,
) -> InvestigationResponse:
    state = initial_state if initial_state is not None else _initial_state(request)
    investigation_id = str(uuid4())
    trace: list[dict[str, Any]] = []
    if siem_context:
        event, alert_data = siem_context
        trace.append(
            make_trace_entry(
                investigation_id,
                1,
                "siem_collector",
                {"event_id": event.event_id, "source": event.source},
                {"stored": True, "event_type": event.event_type, "asset_ip": str(event.asset_ip)},
            )
        )
        trace.append(
            make_trace_entry(
                investigation_id,
                2,
                "alert_detector",
                {"event_id": event.event_id, "event_type": event.event_type},
                {"alert_id": alert_data["alert_id"], "reason": alert_data["reason"]},
            )
        )
    async for _, entry in _walk_investigation(
        state, _run_config(request), investigation_id, start_sequence=len(trace)
    ):
        trace.append(entry)
    response = _build_result(investigation_id, state)
    response.trace = trace
    save_investigation(response.id, response.model_dump(), trace)
    save_asset_history(response.id, response.model_dump())
    response.response_plan = await queue_response(response.id, response.model_dump())
    if response.response_plan:
        response.trace = get_agent_trace(response.id)
        save_investigation(response.id, response.model_dump())
    return response


async def _ingest_event(
    event: SecurityEvent, model: AllModelEnum | None = None
) -> SiemIntakeResponse:
    try:
        stored_event, alert, created = collect(event)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not alert:
        return SiemIntakeResponse(
            event=stored_event, alert=None, investigation=None, created=created
        )
    if alert.investigation_id:
        previous = get_investigation(alert.investigation_id)
        if previous:
            previous["response_plan"] = get_response_plan(alert.investigation_id)
        return SiemIntakeResponse(
            event=stored_event,
            alert=alert.model_dump(mode="json"),
            investigation=InvestigationResponse.model_validate(previous) if previous else None,
            created=False,
        )
    query = (
        f"模拟 SIEM 检测到 {alert.alert_type} 告警，目标 {event.asset_ip}。请调查该事件并给出证据。"
    )
    request = InvestigationRequest(query=query, model=model)
    state = {
        **_initial_state(request),
        "asset_ip": str(event.asset_ip),
        "trigger_event_id": event.event_id,
        "trigger_alert_id": alert.alert_id,
        "alert_type": alert.alert_type,
    }
    response = await _complete_investigation(request, state, (event, alert.model_dump(mode="json")))
    link_alert_investigation(alert.alert_id, response.id)
    latest_alert = get_alert_for_event(event.event_id)
    return SiemIntakeResponse(
        event=stored_event,
        alert=latest_alert,
        investigation=response,
        created=created,
    )


@router.get("/siem/events")
def siem_events(limit: int = 50) -> list[dict[str, Any]]:
    return list_siem_events(limit=max(1, min(limit, 200)))


@router.get("/siem/alerts")
def siem_alerts(limit: int = 50) -> list[dict[str, Any]]:
    return list_siem_alerts(limit=max(1, min(limit, 200)))


@router.post("/siem/events")
async def ingest_siem_event(event: SecurityEvent) -> SiemIntakeResponse:
    """接收一条事件，命中规则时自动启动调查。"""
    return await _ingest_event(event)


@router.post("/siem/simulate")
async def simulate_siem_event(request: SimulationRequest) -> SiemIntakeResponse:
    """生成合成事件并走与普通采集相同的检测链路。"""
    return await _ingest_event(generate_event(request.scenario, request.asset_ip), request.model)


@router.get("/demo-assets")
def demo_assets() -> list[dict[str, Any]]:
    """列出可用于体验的合成资产。"""
    return list_demo_assets()


@router.get("/admin/policy")
def security_policy(_: Annotated[dict, Depends(require_admin)]) -> dict[str, int | bool]:
    return get_security_policy()


@router.patch("/admin/policy")
def change_security_policy(
    request: PolicyUpdate, admin: Annotated[dict, Depends(require_admin)]
) -> dict[str, int | bool]:
    changes = request.model_dump(exclude_unset=True, exclude_none=True)
    try:
        return update_security_policy(changes, admin["username"])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/assets/{asset_ip}/history")
def asset_history(asset_ip: IPv4Address, days: int = 7) -> list[dict[str, Any]]:
    return get_asset_history(str(asset_ip), days=days)


@router.post("/feedback")
def submit_feedback(
    request: FeedbackRequest, user: Annotated[dict, Depends(current_user)]
) -> dict[str, Any]:
    if not get_investigation(request.investigation_id):
        raise HTTPException(status_code=404, detail="未找到调查记录")
    label = "false_positive" if request.label == "wrong" else request.label
    return save_feedback(request.investigation_id, user["username"], label, request.comment)


@router.get("/investigations/{investigation_id}/feedback")
def investigation_feedback(investigation_id: str) -> list[dict[str, Any]]:
    if not get_investigation(investigation_id):
        raise HTTPException(status_code=404, detail="未找到调查记录")
    return get_feedback(investigation_id)


@router.get("/investigations/{investigation_id}/response")
def investigation_response(investigation_id: str) -> dict[str, Any] | None:
    if not get_investigation(investigation_id):
        raise HTTPException(status_code=404, detail="未找到调查记录")
    return get_response_plan(investigation_id)


@router.post("/investigations/{investigation_id}/response/decision")
async def approve_response(
    investigation_id: str,
    request: ApprovalRequest,
    user: Annotated[dict, Depends(require_manager)],
) -> dict[str, Any]:
    try:
        return await resolve_response(investigation_id, request.approved, user["username"])
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/investigations")
def investigation_history(limit: int = 20) -> list[dict[str, Any]]:
    """读取最近的调查记录。"""
    return recent_investigations(max(1, min(limit, 100)))


@router.get("/investigations/{investigation_id}")
def investigation_detail(investigation_id: str) -> InvestigationResponse:
    result = get_investigation(investigation_id)
    if result is None:
        raise HTTPException(status_code=404, detail="未找到调查记录")
    result["response_plan"] = get_response_plan(investigation_id)
    result["trace"] = get_agent_trace(investigation_id)
    return InvestigationResponse.model_validate(result)


@router.get("/investigations/{investigation_id}/trace")
def investigation_trace(investigation_id: str) -> list[dict[str, Any]]:
    if get_investigation(investigation_id) is None:
        raise HTTPException(status_code=404, detail="未找到调查记录")
    return get_agent_trace(investigation_id)


@trace_page_router.get("/trace/{investigation_id}")
def open_trace_page(investigation_id: str) -> RedirectResponse:
    """为轨迹提供可收藏的地址，页面仍由现有 Streamlit 前端呈现。"""
    if get_investigation(investigation_id) is None:
        raise HTTPException(status_code=404, detail="未找到调查记录")
    frontend = os.getenv("SECURITY_FRONTEND_URL") or (
        f"http://127.0.0.1:{os.getenv('STREAMLIT_PORT', '8501')}"
    )
    return RedirectResponse(
        f"{frontend.rstrip('/')}/?{urlencode({'view': 'trace', 'investigation_id': investigation_id})}"
    )


@router.post("/investigate")
async def investigate(request: InvestigationRequest) -> InvestigationResponse:
    """完成一次调查并返回可供前端呈现的结构化证据。"""
    return await _complete_investigation(request)


def _event(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@router.post("/investigate/stream")
async def investigate_stream(request: InvestigationRequest) -> StreamingResponse:
    """逐步推送调查节点的完成事件和最终报告。"""
    config = _run_config(request)

    async def events() -> AsyncGenerator[str, None]:
        state: SecurityState = _initial_state(request)
        investigation_id = str(uuid4())
        trace: list[dict[str, Any]] = []
        try:
            async for node, entry in _walk_investigation(state, config, investigation_id):
                trace.append(entry)
                yield _event(
                    {"type": "step", "node": node, "label": STEP_LABELS[node], "trace": entry}
                )
            response = _build_result(investigation_id, state)
            response.trace = trace
            save_investigation(response.id, response.model_dump(), trace)
            save_asset_history(response.id, response.model_dump())
            response.response_plan = await queue_response(response.id, response.model_dump())
            if response.response_plan:
                response.trace = get_agent_trace(response.id)
                save_investigation(response.id, response.model_dump())
            yield _event({"type": "result", "data": response.model_dump()})
        except Exception:
            yield _event({"type": "error", "message": "调查未能完成，请检查服务日志后重试。"})

    return StreamingResponse(events(), media_type="text/event-stream")
