"""使用持久化 LangGraph interrupt 暂停和恢复模拟响应。"""

from pathlib import Path
from typing import Any, TypedDict

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from security.agents.response_agent import plan_response
from security.repository import (
    append_trace,
    create_response_plan,
    decide_response_plan,
    get_response_plan,
)
from security.response.tools import simulate_action


class ResponseState(TypedDict, total=False):
    investigation_id: str
    actions: list[dict[str, str]]
    approved: bool
    results: list[dict[str, str]]


def approval_gate(state: ResponseState) -> ResponseState:
    decision = interrupt(
        {"investigation_id": state["investigation_id"], "actions": state["actions"]}
    )
    return {"approved": decision["approved"] is True}


def route_approval(state: ResponseState) -> str:
    return "response_tool" if state.get("approved") else END


def response_tool(state: ResponseState) -> ResponseState:
    return {
        "results": [simulate_action(item, state["investigation_id"]) for item in state["actions"]]
    }


builder = StateGraph(ResponseState)
builder.add_node("human_approval", approval_gate)
builder.add_node("response_tool", response_tool)
builder.add_edge(START, "human_approval")
builder.add_conditional_edges("human_approval", route_approval)
builder.add_edge("response_tool", END)


def _checkpoint_path() -> str:
    path = (
        Path(__file__).resolve().parents[3] / ".runtime-tools" / "security_response_checkpoints.db"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


async def queue_response(investigation_id: str, result: dict[str, Any]) -> dict | None:
    actions = plan_response(result)
    if not actions:
        return None
    existing = get_response_plan(investigation_id)
    if existing:
        return existing
    plan = create_response_plan(investigation_id, actions)
    config = {"configurable": {"thread_id": investigation_id}}
    async with AsyncSqliteSaver.from_conn_string(_checkpoint_path()) as saver:
        graph = builder.compile(checkpointer=saver)
        await graph.ainvoke({"investigation_id": investigation_id, "actions": actions}, config)
    append_trace(investigation_id, "response_planner", "响应建议", {}, {"actions": actions})
    append_trace(
        investigation_id, "human_approval", "等待审批", {"actions": actions}, {"status": "待审批"}
    )
    return plan


async def resolve_response(investigation_id: str, approved: bool, actor: str) -> dict:
    plan = get_response_plan(investigation_id)
    if not plan or plan["status"] != "待审批":
        raise ValueError("不存在待审批的响应方案")
    config = {"configurable": {"thread_id": investigation_id}}
    async with AsyncSqliteSaver.from_conn_string(_checkpoint_path()) as saver:
        graph = builder.compile(checkpointer=saver)
        snapshot = await graph.aget_state(config)
        if "human_approval" not in snapshot.next:
            raise ValueError("审批检查点不存在或已完成")
        state = await graph.ainvoke(Command(resume={"approved": approved}), config)
    results = state.get("results", []) if approved else []
    status = "已模拟执行" if approved else "已拒绝"
    if not decide_response_plan(investigation_id, actor, status, results):
        raise ValueError("响应方案已经处理")
    append_trace(
        investigation_id,
        "human_approval",
        "审批结果",
        {"actor": actor},
        {"approved": approved, "status": status},
    )
    if approved:
        append_trace(
            investigation_id,
            "response_tool",
            "模拟执行",
            {"actions": plan["actions"]},
            {"results": results},
        )
    return get_response_plan(investigation_id) or plan
