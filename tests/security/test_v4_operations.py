"""验证资产记忆、反馈、角色边界和持久化人工审批。"""

import json
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage

from security.auth import hash_password
from security.repository import (
    create_user,
    get_asset_history,
    get_feedback,
    save_asset_history,
    save_investigation,
)
from service import app


@pytest.fixture(autouse=True)
def isolated_v4(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_DEMO_DB_PATH", str(tmp_path / "security.db"))
    monkeypatch.setenv("SECURITY_RAG_MODE", "lexical")
    monkeypatch.setenv("SECURITY_JWT_SECRET", "test-only-secret-with-at-least-32-characters")
    monkeypatch.setattr(
        "security.response.approval._checkpoint_path", lambda: str(tmp_path / "response.db")
    )
    planner = AsyncMock()
    planner.ainvoke.return_value = AIMessage(
        content=json.dumps(
            {"tasks": ["asset_check", "log_analysis", "threat_check", "security_rag"]}
        )
    )
    report = AsyncMock()
    report.ainvoke.return_value = AIMessage(content="演示事件需要人工复核。")
    monkeypatch.setattr("security.planner.get_model", lambda _: planner)
    monkeypatch.setattr("security.workflow.get_model", lambda _: report)
    create_user("admin", hash_password("AdminPassword123!"), "ADMIN")
    create_user("analyst", hash_password("AnalystPassword123!"), "ANALYST")


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post(
        "/security/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_auth_feedback_and_persisted_response_approval():
    with TestClient(app) as client:
        assert client.get("/security/demo-assets").status_code == 401
        assert (
            client.post(
                "/security/auth/login", json={"username": "admin", "password": "wrong"}
            ).status_code
            == 401
        )
        analyst = _login(client, "analyst", "AnalystPassword123!")
        admin = _login(client, "admin", "AdminPassword123!")
        assert client.get("/security/demo-assets", headers=analyst).status_code == 200
        assert client.get("/security/auth/users", headers=analyst).status_code == 403
        assert (
            client.post(
                "/security/auth/users",
                headers=admin,
                json={"username": "manager", "password": "ManagerPassword123!", "role": "MANAGER"},
            ).status_code
            == 201
        )
        result = client.post(
            "/security/siem/simulate",
            headers=analyst,
            json={"scenario": "SSH_FAILED_LOGIN", "asset_ip": "192.168.1.10"},
        )
        assert result.status_code == 200
        investigation = result.json()["investigation"]
        identifier = investigation["id"]
        assert investigation["response_plan"]["status"] == "待审批"
        assert {item["type"] for item in investigation["response_plan"]["actions"]} == {
            "block_ip",
            "create_ticket",
        }
        assert (
            client.post(
                f"/security/investigations/{identifier}/response/decision",
                headers=analyst,
                json={"approved": True},
            ).status_code
            == 403
        )
        feedback = client.post(
            "/security/feedback",
            headers=analyst,
            json={"investigation_id": identifier, "label": "false_positive", "comment": "演示误报"},
        )
        assert feedback.status_code == 200
        assert get_feedback(identifier)[0]["label"] == "false_positive"
        assert len(get_asset_history("192.168.1.10")) == 1
        assert get_asset_history("192.168.1.10")[0]["feedback_labels"] == ["false_positive"]

    # 新请求和新检查点连接仍可从中断处恢复。
    with TestClient(app) as client:
        manager = _login(client, "manager", "ManagerPassword123!")
        admin = _login(client, "admin", "AdminPassword123!")
        decided = client.post(
            f"/security/investigations/{identifier}/response/decision",
            headers=manager,
            json={"approved": True},
        )
        assert decided.status_code == 200
        assert decided.json()["status"] == "已模拟执行"
        assert all(item["status"] == "模拟完成" for item in decided.json()["results"])
        assert all("未" in item["message"] for item in decided.json()["results"])
        assert (
            client.post(
                f"/security/investigations/{identifier}/response/decision",
                headers=manager,
                json={"approved": True},
            ).status_code
            == 409
        )
        trace = client.get(f"/security/investigations/{identifier}/trace", headers=manager).json()
        assert trace[-1]["node_name"] == "response_tool"
        changed = client.patch(
            "/security/auth/users/manager",
            headers=admin,
            json={"role": "ANALYST", "active": True},
        )
        assert changed.status_code == 200
        assert (
            client.post(
                f"/security/investigations/{identifier}/response/decision",
                headers=manager,
                json={"approved": True},
            ).status_code
            == 403
        )


def test_history_trend_and_rejected_response():
    for score in (10, 20, 30):
        identifier = f"history-{score}"
        previous = {
            "asset_ip": "192.168.1.20",
            "query": "历史测试",
            "risk_level": "中",
            "risk_score": score,
            "findings": [],
        }
        save_investigation(identifier, previous)
        save_asset_history(identifier, previous)
    with TestClient(app) as client:
        admin = _login(client, "admin", "AdminPassword123!")
        response = client.post(
            "/security/siem/simulate",
            headers=admin,
            json={"scenario": "PORT_SCAN", "asset_ip": "192.168.1.20"},
        )
        assert response.status_code == 200
        result = response.json()["investigation"]
        assert len(result["history"]) == 3
        assert any(item["title"] == "资产近期风险持续上升" for item in result["findings"])
        assert result["risk_score"] >= 80
        identifier = result["id"]
        rejected = client.post(
            f"/security/investigations/{identifier}/response/decision",
            headers=admin,
            json={"approved": False},
        )
        assert rejected.status_code == 200
        assert rejected.json()["status"] == "已拒绝"
        assert rejected.json()["results"] == []


def test_admin_policy_changes_detection_and_simulated_tools():
    with TestClient(app) as client:
        admin = _login(client, "admin", "AdminPassword123!")
        analyst = _login(client, "analyst", "AnalystPassword123!")
        assert client.get("/security/admin/policy", headers=analyst).status_code == 403
        changed = client.patch(
            "/security/admin/policy",
            headers=admin,
            json={"ssh_failed_threshold": 1000, "simulate_block_ip": False},
        )
        assert changed.status_code == 200
        assert changed.json()["ssh_failed_threshold"] == 1000
        below = client.post(
            "/security/siem/simulate",
            headers=admin,
            json={"scenario": "SSH_FAILED_LOGIN", "asset_ip": "192.168.1.10"},
        )
        assert below.status_code == 200
        assert below.json()["alert"] is None
        assert (
            client.patch(
                "/security/admin/policy", headers=admin, json={"ssh_failed_threshold": 100}
            ).status_code
            == 200
        )
        triggered = client.post(
            "/security/siem/simulate",
            headers=admin,
            json={"scenario": "SSH_FAILED_LOGIN", "asset_ip": "192.168.1.10"},
        )
        assert triggered.status_code == 200
        actions = triggered.json()["investigation"]["response_plan"]["actions"]
        assert [action["type"] for action in actions] == ["create_ticket"]


def test_existing_investigations_backfill_into_asset_history():
    previous = {
        "asset_ip": "192.168.1.20",
        "query": "V3 历史调查",
        "risk_level": "低",
        "risk_score": 12,
        "findings": [{"title": "旧记录"}],
    }
    save_investigation("legacy-v3", previous)
    history = get_asset_history("192.168.1.20")
    assert len(history) == 1
    assert history[0]["investigation_id"] == "legacy-v3"
    assert history[0]["findings"][0]["title"] == "旧记录"
