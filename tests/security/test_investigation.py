"""验证安全调查的证据链、降级行为和接口。"""

import json
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage, HumanMessage

from security.auth import current_user
from security.workflow import security_investigation_agent
from service import app


@pytest.fixture(autouse=True)
def isolated_demo_database(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_DEMO_DB_PATH", str(tmp_path / "security.db"))
    monkeypatch.setenv("SECURITY_RAG_MODE", "lexical")
    security_investigation_agent.checkpointer = None
    app.dependency_overrides[current_user] = lambda: {
        "username": "test-admin",
        "role": "ADMIN",
        "active": 1,
    }
    yield
    security_investigation_agent.checkpointer = None
    app.dependency_overrides.pop(current_user, None)


@pytest.fixture
def stub_models(monkeypatch):
    planner = AsyncMock()
    planner.ainvoke.return_value = AIMessage(
        content=json.dumps(
            {
                "tasks": [
                    "asset_check",
                    "log_analysis",
                    "vulnerability_check",
                    "threat_check",
                    "security_rag",
                ],
                "reason": "调查主机风险",
            }
        )
    )
    report = AsyncMock()
    report.ainvoke.return_value = AIMessage(content="演示证据显示异常登录与关联漏洞，请人工复核。")
    monkeypatch.setattr("security.planner.get_model", lambda _: planner)
    monkeypatch.setattr("security.workflow.get_model", lambda _: report)
    return planner, report


@pytest.mark.asyncio
async def test_high_risk_investigation_links_source_ip_and_evidence(stub_models):
    result = await security_investigation_agent.ainvoke(
        {"messages": [HumanMessage(content="调查 192.168.1.10 的安全风险")]},
        config={"configurable": {"thread_id": "test-high-risk"}},
    )

    assert result["risk_level"] == "高"
    assert result["asset_info"]["hostname"] == "web-prod-01"
    assert any(item["ip"] == "203.0.113.45" for item in result["threat_info"])
    assert any("LOG-001" in item["evidence_ids"] for item in result["findings"])
    assert "本地合成演示数据" in result["report"]
    assert "人工确认" in result["report"]
    assert result["planner_mode"] == "模型规划"
    assert any(item["id"] == "ATTACK-T1110" for item in result["knowledge"])
    assert result["mitre_matches"][0]["id"] == "T1110"
    assert any(item.get("attack", {}).get("id") == "T1110" for item in result["findings"])
    assert not any(item["id"] == "ATTACK-T1548" for item in result["knowledge"])


@pytest.mark.asyncio
async def test_missing_asset_does_not_invent_findings(stub_models):
    result = await security_investigation_agent.ainvoke(
        {"messages": [HumanMessage(content="调查 192.0.2.200 的安全风险")]},
        config={"configurable": {"thread_id": "test-unknown"}},
    )

    assert result["risk_level"] == "待确认"
    assert result["asset_info"] == {}
    assert "不能判断该主机" in result["findings"][0]["detail"]
    assert not any(item["kind"] == "资产" for item in result["evidence"])


def test_security_api_streams_and_saves_result(stub_models):
    with TestClient(app) as client:
        assets = client.get("/security/demo-assets")
        assert assets.status_code == 200
        assert len(assets.json()) == 3

        with client.stream(
            "POST",
            "/security/investigate/stream",
            json={"query": "请调查 10.0.0.5 最近的异常活动"},
        ) as response:
            assert response.status_code == 200
            events = [
                json.loads(line[6:]) for line in response.iter_lines() if line.startswith("data: ")
            ]

        assert {event["node"] for event in events if event["type"] == "step"} >= {
            "asset_agent",
            "log_agent",
            "vulnerability_agent",
            "threat_agent",
            "rag_agent",
            "risk_agent",
            "report_agent",
        }
        result = next(event["data"] for event in events if event["type"] == "result")
        assert result["risk_level"] == "高"
        detail = client.get(f"/security/investigations/{result['id']}")
        assert detail.status_code == 200
        assert detail.json()["report"] == result["report"]
        trace = client.get(f"/security/investigations/{result['id']}/trace")
        assert trace.status_code == 200
        assert [item["sequence"] for item in trace.json()] == list(range(1, len(trace.json()) + 1))
        assert any(item["node_name"] == "planner_agent" for item in trace.json())
        assert any(item["node_name"] == "mitre_mapper" for item in trace.json())
        assert len(result["trace"]) == len(trace.json())
        page = client.get(f"/trace/{result['id']}", follow_redirects=False)
        assert page.status_code == 307
        assert f"investigation_id={result['id']}" in page.headers["location"]


def test_siem_alert_automatically_investigates_only_triggering_event(stub_models):
    with TestClient(app) as client:
        response = client.post(
            "/security/siem/simulate",
            json={"scenario": "SSH_FAILED_LOGIN", "asset_ip": "192.168.1.10"},
        )
        assert response.status_code == 200
        data = response.json()
        event_id = data["event"]["event_id"]
        assert data["alert"]["alert_type"] == "BRUTE_FORCE"
        assert data["alert"]["investigation_id"] == data["investigation"]["id"]
        assert [item["id"] for item in data["investigation"]["logs"]] == [event_id]
        assert data["investigation"]["risk_level"] == "高"
        assert "log_analysis" in data["investigation"]["completed_tasks"]
        assert data["investigation"]["mitre_matches"][0]["id"] == "T1110"
        assert any(item["node_name"] == "report_agent" for item in data["investigation"]["trace"])
        assert data["investigation"]["response_plan"]["status"] == "待审批"
        assert [item["node_name"] for item in data["investigation"]["trace"][:2]] == [
            "siem_collector",
            "alert_detector",
        ]

        replay = client.post("/security/siem/events", json=data["event"])
        assert replay.status_code == 200
        assert replay.json()["created"] is False
        assert replay.json()["investigation"]["id"] == data["investigation"]["id"]


def test_siem_detector_does_not_investigate_below_threshold():
    with TestClient(app) as client:
        response = client.post(
            "/security/siem/events",
            json={
                "event_id": "EVT-BELOW-THRESHOLD",
                "asset_ip": "192.168.1.20",
                "event_type": "SSH_FAILED_LOGIN",
                "timestamp": "2026-10-12T01:00:00Z",
                "source": "演示测试",
                "severity": "LOW",
                "raw_data": {"source_ip": "192.0.2.8", "count": 8},
            },
        )
        assert response.status_code == 200
        assert response.json()["alert"] is None
        assert response.json()["investigation"] is None


@pytest.mark.parametrize(
    ("scenario", "technique_id"),
    [("COMMAND_EXECUTION", "T1059"), ("PRIVILEGE_ESCALATION", "T1548")],
)
def test_siem_event_maps_supported_mitre_technique(stub_models, scenario, technique_id):
    with TestClient(app) as client:
        response = client.post(
            "/security/siem/simulate",
            json={"scenario": scenario, "asset_ip": "192.168.1.20"},
        )
        assert response.status_code == 200
        result = response.json()["investigation"]
        assert technique_id in [item["id"] for item in result["mitre_matches"]]
        assert any(item.get("attack", {}).get("id") == technique_id for item in result["findings"])
        assert technique_id in result["report"]


@pytest.mark.parametrize(
    ("scenario", "finding_title"),
    [("PORT_SCAN", "检测到端口扫描线索"), ("MALWARE", "演示恶意文件特征告警")],
)
def test_other_siem_scenarios_keep_event_evidence_without_forced_mapping(
    stub_models, scenario, finding_title
):
    with TestClient(app) as client:
        response = client.post(
            "/security/siem/simulate",
            json={"scenario": scenario, "asset_ip": "192.168.1.20"},
        )
        assert response.status_code == 200
        data = response.json()
        event_id = data["event"]["event_id"]
        findings = data["investigation"]["findings"]
        assert any(
            item["title"] == finding_title and event_id in item["evidence_ids"] for item in findings
        )
        assert data["investigation"]["mitre_matches"] == []


@pytest.mark.asyncio
async def test_cve_question_uses_only_knowledge_without_claiming_host_risk(stub_models):
    result = await security_investigation_agent.ainvoke(
        {"messages": [HumanMessage(content="CVE-2024-6387 严重吗？怎么修复？")]},
        config={"configurable": {"thread_id": "test-cve-only"}},
    )

    assert result["investigation_plan"] == ["security_rag"]
    assert result["completed_tasks"] == ["security_rag"]
    assert result["risk_level"] == "待确认"
    assert result["asset_ip"] is None
    assert result["knowledge"][0]["id"] == "CVE-2024-6387"
    assert result["findings"][0]["title"] == "安全知识参考"
    assert "这是安全知识问题" in result["plan_reason"]
    assert "请提供" not in result["plan_reason"]
    assert "CVE-2024-6387" in result["report"]
    assert "核对该 CVE 的修复方案" in result["report"]


@pytest.mark.asyncio
async def test_log_evidence_adds_follow_up_tasks(stub_models):
    planner, _ = stub_models
    planner.ainvoke.return_value = AIMessage(
        content='{"tasks":["asset_check","log_analysis"],"reason":"先查日志"}'
    )
    result = await security_investigation_agent.ainvoke(
        {"messages": [HumanMessage(content="调查 10.0.0.5 的登录异常")]},
        config={"configurable": {"thread_id": "test-follow-up"}},
    )

    assert result["investigation_plan"] == [
        "asset_check",
        "asset_history_check",
        "log_analysis",
        "threat_check",
        "security_rag",
    ]
    assert "vulnerability_check" not in result["completed_tasks"]
    assert any("根据日志异常追加" in item for item in result["execution_trace"])


@pytest.mark.asyncio
async def test_yesterday_query_does_not_use_todays_logs(stub_models):
    planner, _ = stub_models
    planner.ainvoke.return_value = AIMessage(content='{"tasks":["log_analysis"]}')
    result = await security_investigation_agent.ainvoke(
        {"messages": [HumanMessage(content="192.168.1.10 昨天凌晨登录异常吗？")]},
        config={"configurable": {"thread_id": "test-yesterday"}},
    )

    assert result["logs"] == []
    assert result["risk_level"] == "待确认"
    assert "昨天凌晨" in result["log_scope_note"]


@pytest.mark.asyncio
async def test_asset_lookup_alone_does_not_claim_low_risk(stub_models):
    planner, _ = stub_models
    planner.ainvoke.return_value = AIMessage(content='{"tasks":["asset_check"]}')
    result = await security_investigation_agent.ainvoke(
        {"messages": [HumanMessage(content="192.168.1.20 是什么资产？")]},
        config={"configurable": {"thread_id": "test-asset-only"}},
    )

    assert result["completed_tasks"] == ["asset_check", "asset_history_check"]
    assert result["risk_level"] == "待确认"
    assert result["findings"][0]["title"] == "尚未开展安全检查"
