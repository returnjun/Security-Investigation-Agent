"""让模型选择调查任务，并对计划做严格校验与回退。"""

import json
import re
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field

from core import get_model, settings
from security.state import SecurityState

TaskName = Literal[
    "asset_check",
    "asset_history_check",
    "log_analysis",
    "vulnerability_check",
    "threat_check",
    "security_rag",
]
TASKS = set(TaskName.__args__)
TASK_ORDER = [
    "asset_check",
    "asset_history_check",
    "log_analysis",
    "vulnerability_check",
    "threat_check",
    "security_rag",
]


class InvestigationPlan(BaseModel):
    tasks: list[TaskName] = Field(default_factory=list, max_length=6)
    reason: str = Field(default="", max_length=300)


PLANNER_PROMPT = """你是安全事件调查规划员。只输出一个 JSON 对象，格式：
{"tasks":["asset_check"],"reason":"简短中文理由"}
可选任务：asset_check（资产）、asset_history_check（资产近7天调查历史）、log_analysis（登录与安全日志）、
vulnerability_check（资产漏洞）、threat_check（日志来源 IP 信誉）、
security_rag（CVE、MITRE ATT&CK 和安全规范知识）。
按问题需要选择，勿默认全选。纯 CVE 或知识问答只选 security_rag。
登录异常优先 log_analysis，可选择 asset_check/security_rag；不涉及漏洞时不要选 vulnerability_check。
任何具体资产调查都应查询资产历史；需要资产数据的任务必须有明确目标 IP；没有 IP 时只能选择 security_rag。
纯 CVE 或安全知识问题无需目标 IP，不要要求用户补充；只有用户问的是具体主机或日志，
却没有提供 IP 时，才在 reason 中说明需要补充目标 IP。
不要输出其他任务或执行任何处置动作。"""

ALERT_REQUIRED_TASKS = {
    "BRUTE_FORCE": ["asset_check", "log_analysis", "threat_check", "security_rag"],
    "PORT_SCAN": ["asset_check", "log_analysis", "threat_check"],
    "PRIVILEGE_ESCALATION": ["asset_check", "log_analysis", "security_rag"],
    "COMMAND_EXECUTION": ["asset_check", "log_analysis", "security_rag"],
    "MALWARE": ["asset_check", "log_analysis", "security_rag"],
}


def _fallback_tasks(query: str, asset_ip: str | None, cve_id: str | None) -> list[str]:
    lowered = query.lower()
    if not asset_ip:
        return (
            ["security_rag"]
            if cve_id
            or any(
                word in lowered
                for word in ("ssh", "暴力破解", "漏洞", "攻击", "安全", "怎么", "如何")
            )
            else []
        )
    if cve_id or any(word in lowered for word in ("漏洞", "修复", "cve")):
        return ["asset_check", "vulnerability_check", "security_rag"]
    if any(word in lowered for word in ("登录", "日志", "凌晨", "ssh")) and not any(
        word in lowered for word in ("整体", "全面", "风险")
    ):
        return ["asset_check", "log_analysis", "security_rag"]
    return [
        "asset_check",
        "log_analysis",
        "vulnerability_check",
        "threat_check",
        "security_rag",
    ]


def _validated_tasks(tasks: list[str], asset_ip: str | None) -> list[str]:
    result = list(dict.fromkeys(task for task in tasks if task in TASKS))
    if not asset_ip:
        result = [task for task in result if task == "security_rag"]
    else:
        if "asset_history_check" not in result:
            result.append("asset_history_check")
        if "threat_check" in result and "log_analysis" not in result:
            result.append("log_analysis")
    return [task for task in TASK_ORDER if task in result]


async def planner_agent(state: SecurityState, config: RunnableConfig) -> SecurityState:
    """用模型生成计划；解析失败时提供可复现的规则计划。"""
    query = state["query"]
    asset_ip = state.get("asset_ip")
    cve_id = state.get("cve_id")
    mode = "模型规划"
    reason = "根据问题选择所需调查任务。"
    try:
        model_name = config.get("configurable", {}).get("model", settings.DEFAULT_MODEL)
        model = get_model(model_name)
        response = await model.ainvoke(
            [
                SystemMessage(content=PLANNER_PROMPT),
                HumanMessage(
                    content=json.dumps(
                        {
                            "query": query,
                            "asset_ip": asset_ip,
                            "cve_id": cve_id,
                            "siem_alert_type": state.get("alert_type"),
                        },
                        ensure_ascii=False,
                    )
                ),
            ],
            config=config,
        )
        content = response.content if isinstance(response.content, str) else str(response.content)
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            raise ValueError("规划器未返回 JSON")
        parsed = InvestigationPlan.model_validate(json.loads(match.group()))
        tasks = _validated_tasks(parsed.tasks, asset_ip)
        if not tasks:
            raise ValueError("规划器未选择可执行任务")
        reason = parsed.reason or reason
    except Exception:
        tasks = _validated_tasks(_fallback_tasks(query, asset_ip, cve_id), asset_ip)
        mode = "规则回退"
        reason = "模型规划暂不可用，按问题关键词生成保守计划。"
    if state.get("alert_type") and asset_ip:
        required = ALERT_REQUIRED_TASKS.get(state["alert_type"], [])
        missing = [task for task in required if task not in tasks]
        if missing:
            tasks = _validated_tasks([*tasks, *missing], asset_ip)
            reason += " 告警调查补足必要的资产与事件核查任务。"
    host_question = any(word in query.lower() for word in ("服务器", "主机", "登录", "日志"))
    if not asset_ip and not host_question and tasks == ["security_rag"]:
        reason = "这是安全知识问题，先检索参考资料；具体资产风险需要另行核实。"
    if not asset_ip and host_question:
        reason += " 如需分析具体主机，请提供目标 IPv4 地址。"
    return {
        "investigation_plan": tasks,
        "completed_tasks": [],
        "planner_mode": mode,
        "plan_reason": reason,
        "execution_trace": [f"{mode}：{', '.join(tasks) or '无可执行任务'}"],
    }
