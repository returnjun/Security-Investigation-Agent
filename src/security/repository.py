"""SQLite 演示数据访问层。所有查询均使用参数化 SQL。"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from security.demo_data import ASSETS, LOGS, REPUTATIONS, VULNERABILITIES


def database_path() -> Path:
    configured = os.getenv("SECURITY_DB_PATH") or os.getenv("SECURITY_DEMO_DB_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    data_dir = Path(__file__).resolve().parents[2] / "data"
    legacy = data_dir / "security_demo.db"
    return legacy if legacy.exists() else data_dir / "security_investigation.db"


def _connect() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS assets (
            ip TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            operating_system TEXT NOT NULL,
            owner TEXT NOT NULL,
            environment TEXT NOT NULL,
            importance TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_logs (
            id TEXT PRIMARY KEY,
            asset_ip TEXT NOT NULL,
            event TEXT NOT NULL,
            level TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            minutes_ago INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            asset_ip TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            solution TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip TEXT PRIMARY KEY,
            score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            note TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            asset_ip TEXT,
            query TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            result_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            asset_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            raw_data_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_security_events_asset_time
            ON security_events(asset_ip, timestamp DESC);
        CREATE TABLE IF NOT EXISTS security_alerts (
            alert_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE REFERENCES security_events(event_id),
            asset_ip TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            investigation_id TEXT
        );
        CREATE TABLE IF NOT EXISTS agent_trace (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL REFERENCES investigations(id),
            sequence INTEGER NOT NULL,
            node_name TEXT NOT NULL,
            event_type TEXT NOT NULL,
            input_json TEXT NOT NULL,
            output_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(investigation_id, sequence)
        );
        CREATE INDEX IF NOT EXISTS idx_agent_trace_investigation
            ON agent_trace(investigation_id, sequence);
        CREATE TABLE IF NOT EXISTS asset_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_ip TEXT NOT NULL,
            investigation_id TEXT NOT NULL UNIQUE REFERENCES investigations(id),
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            findings_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_asset_history_asset_time
            ON asset_history(asset_ip, created_at DESC);
        CREATE TABLE IF NOT EXISTS security_feedback (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL REFERENCES investigations(id),
            analyst TEXT NOT NULL,
            label TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(investigation_id, analyst)
        );
        CREATE TABLE IF NOT EXISTS security_users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS response_plans (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL UNIQUE REFERENCES investigations(id),
            actions_json TEXT NOT NULL,
            status TEXT NOT NULL,
            proposed_at TEXT NOT NULL,
            decided_by TEXT,
            decided_at TEXT,
            results_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS security_policy (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    connection.executemany("INSERT OR IGNORE INTO assets VALUES (?, ?, ?, ?, ?, ?)", ASSETS)
    connection.executemany("INSERT OR IGNORE INTO security_logs VALUES (?, ?, ?, ?, ?, ?, ?)", LOGS)
    connection.executemany(
        "INSERT OR IGNORE INTO vulnerabilities VALUES (?, ?, ?, ?, ?)", VULNERABILITIES
    )
    connection.executemany("INSERT OR IGNORE INTO ip_reputation VALUES (?, ?, ?, ?)", REPUTATIONS)
    # 兼容 V3 已保存的调查：首次访问时将有资产的旧报告补入资产历史。
    previous = connection.execute(
        "SELECT id, created_at, asset_ip, risk_level, risk_score, result_json "
        "FROM investigations WHERE asset_ip IS NOT NULL "
        "AND id NOT IN (SELECT investigation_id FROM asset_history)"
    ).fetchall()
    for item in previous:
        try:
            findings = json.loads(item["result_json"]).get("findings", [])
        except (ValueError, TypeError):
            findings = []
        connection.execute(
            "INSERT OR IGNORE INTO asset_history "
            "(asset_ip, investigation_id, risk_level, risk_score, findings_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                item["asset_ip"],
                item["id"],
                item["risk_level"],
                item["risk_score"],
                json.dumps(findings, ensure_ascii=False),
                item["created_at"],
            ),
        )
    connection.commit()
    return connection


def list_demo_assets() -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT ip, hostname, operating_system, owner, environment, importance "
            "FROM assets ORDER BY ip"
        ).fetchall()
    return [dict(row) for row in rows]


def get_asset(ip: str) -> dict[str, Any]:
    with closing(_connect()) as connection:
        row = connection.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else {}


def _event_log(event: dict[str, Any]) -> dict[str, Any]:
    names = {
        "SSH_FAILED_LOGIN": "SSH 登录失败",
        "PORT_SCAN": "端口扫描",
        "PRIVILEGE_ESCALATION": "异常提权",
        "COMMAND_EXECUTION": "命令解释器执行",
        "MALWARE": "恶意文件告警",
    }
    raw = event["raw_data"]
    return {
        "id": event["event_id"],
        "asset_ip": event["asset_ip"],
        "event": names[event["event_type"]],
        "level": {"HIGH": "高", "MEDIUM": "中", "LOW": "低"}[event["severity"]],
        "source_ip": raw.get("source_ip", "未知"),
        "event_count": raw.get("count", 1),
        "time": event["timestamp"],
        "event_type": event["event_type"],
        "raw_data": raw,
    }


def get_security_logs(ip: str, event_id: str | None = None) -> list[dict[str, Any]]:
    """告警调查只读触发事件；手动调查读取全部演示日志。"""
    if event_id:
        event = get_siem_event(event_id)
        return [_event_log(event)] if event and event["asset_ip"] == ip else []
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, asset_ip, event, level, source_ip, event_count, minutes_ago "
            "FROM security_logs WHERE asset_ip = ? ORDER BY minutes_ago DESC",
            (ip,),
        ).fetchall()
    now = datetime.now(UTC)
    demo_logs = [
        {
            **{key: row[key] for key in row.keys() if key != "minutes_ago"},
            "time": (now - timedelta(minutes=row["minutes_ago"])).isoformat(),
        }
        for row in rows
    ]
    return [*demo_logs, *[_event_log(event) for event in list_siem_events(asset_ip=ip, limit=200)]]


def save_siem_event(event: dict[str, Any]) -> None:
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT INTO security_events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event["event_id"],
                event["timestamp"],
                event["source"],
                event["asset_ip"],
                event["event_type"],
                event["severity"],
                json.dumps(event["raw_data"], ensure_ascii=False),
            ),
        )
        connection.commit()


def _decode_event(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["raw_data"] = json.loads(result.pop("raw_data_json"))
    return result


def get_siem_event(event_id: str) -> dict[str, Any] | None:
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT * FROM security_events WHERE event_id = ?", (event_id,)
        ).fetchone()
    return _decode_event(row) if row else None


def list_siem_events(asset_ip: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        if asset_ip:
            rows = connection.execute(
                "SELECT * FROM security_events WHERE asset_ip = ? ORDER BY timestamp DESC LIMIT ?",
                (asset_ip, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
    return [_decode_event(row) for row in rows]


def save_siem_alert(alert: dict[str, Any]) -> None:
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT INTO security_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert["alert_id"],
                alert["event_id"],
                alert["asset_ip"],
                alert["alert_type"],
                alert["severity"],
                alert["reason"],
                alert["created_at"],
                alert.get("investigation_id"),
            ),
        )
        connection.commit()


def get_alert_for_event(event_id: str) -> dict[str, Any] | None:
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT * FROM security_alerts WHERE event_id = ?", (event_id,)
        ).fetchone()
    return dict(row) if row else None


def list_siem_alerts(limit: int = 50) -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def link_alert_investigation(alert_id: str, investigation_id: str) -> None:
    with closing(_connect()) as connection:
        connection.execute(
            "UPDATE security_alerts SET investigation_id = ? WHERE alert_id = ?",
            (investigation_id, alert_id),
        )
        connection.commit()


def get_vulnerabilities(ip: str) -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, asset_ip, severity, description, solution "
            "FROM vulnerabilities WHERE asset_ip = ? ORDER BY severity DESC",
            (ip,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_ip_reputation(ip: str) -> dict[str, Any]:
    with closing(_connect()) as connection:
        row = connection.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,)).fetchone()
    return (
        dict(row)
        if row
        else {"ip": ip, "score": 0, "classification": "未知", "note": "无演示情报记录"}
    )


def save_investigation(
    investigation_id: str, result: dict[str, Any], trace: list[dict[str, Any]] | None = None
) -> None:
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO investigations VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                investigation_id,
                datetime.now(UTC).isoformat(),
                result.get("asset_ip"),
                result["query"],
                result["risk_level"],
                result["risk_score"],
                json.dumps(result, ensure_ascii=False),
            ),
        )
        if trace:
            connection.executemany(
                "INSERT OR REPLACE INTO agent_trace VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        item["id"],
                        investigation_id,
                        item["sequence"],
                        item["node_name"],
                        item["event_type"],
                        json.dumps(item["input"], ensure_ascii=False),
                        json.dumps(item["output"], ensure_ascii=False),
                        item["created_at"],
                    )
                    for item in trace
                ],
            )
        connection.commit()


def recent_investigations(limit: int = 20) -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, created_at, asset_ip, query, risk_level, risk_score "
            "FROM investigations ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_investigation(investigation_id: str) -> dict[str, Any] | None:
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT result_json FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
    return json.loads(row["result_json"]) if row else None


def get_agent_trace(investigation_id: str) -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM agent_trace WHERE investigation_id = ? ORDER BY sequence",
            (investigation_id,),
        ).fetchall()
    return [
        {
            **{
                key: row[key]
                for key in (
                    "id",
                    "investigation_id",
                    "sequence",
                    "node_name",
                    "event_type",
                    "created_at",
                )
            },
            "input": json.loads(row["input_json"]),
            "output": json.loads(row["output_json"]),
        }
        for row in rows
    ]


def get_asset_history(asset_ip: str, days: int = 7) -> list[dict[str, Any]]:
    """读取某资产指定天数内已经完成的调查，不包含正在进行的调查。"""
    since = (datetime.now(UTC) - timedelta(days=max(1, min(days, 365)))).isoformat()
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, asset_ip, investigation_id, risk_level, risk_score, "
            "findings_json, created_at FROM asset_history "
            "WHERE asset_ip = ? AND created_at >= ? ORDER BY created_at ASC, id ASC LIMIT 200",
            (asset_ip, since),
        ).fetchall()
        feedback = connection.execute(
            "SELECT investigation_id, label FROM security_feedback WHERE investigation_id IN "
            "(SELECT investigation_id FROM asset_history WHERE asset_ip=? AND created_at>=?)",
            (asset_ip, since),
        ).fetchall()
    labels: dict[str, list[str]] = {}
    for item in feedback:
        labels.setdefault(item["investigation_id"], []).append(item["label"])
    return [
        {
            **{
                key: row[key]
                for key in (
                    "id",
                    "asset_ip",
                    "investigation_id",
                    "risk_level",
                    "risk_score",
                    "created_at",
                )
            },
            "findings": json.loads(row["findings_json"]),
            "feedback_labels": labels.get(row["investigation_id"], []),
        }
        for row in rows
    ]


def save_asset_history(investigation_id: str, result: dict[str, Any]) -> None:
    if not result.get("asset_ip"):
        return
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO asset_history "
            "(asset_ip, investigation_id, risk_level, risk_score, findings_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                result["asset_ip"],
                investigation_id,
                result["risk_level"],
                result["risk_score"],
                json.dumps(result["findings"], ensure_ascii=False),
                datetime.now(UTC).isoformat(),
            ),
        )
        connection.commit()


def save_feedback(investigation_id: str, analyst: str, label: str, comment: str) -> dict[str, Any]:
    feedback = {
        "id": str(uuid4()),
        "investigation_id": investigation_id,
        "analyst": analyst,
        "label": label,
        "comment": comment,
        "created_at": datetime.now(UTC).isoformat(),
    }
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT INTO security_feedback VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(investigation_id, analyst) DO UPDATE SET "
            "label=excluded.label, comment=excluded.comment, created_at=excluded.created_at",
            tuple(feedback.values()),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM security_feedback WHERE investigation_id=? AND analyst=?",
            (investigation_id, analyst),
        ).fetchone()
    return dict(row)


def get_feedback(investigation_id: str) -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM security_feedback WHERE investigation_id=? ORDER BY created_at DESC",
            (investigation_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def user_count() -> int:
    with closing(_connect()) as connection:
        return connection.execute("SELECT COUNT(*) FROM security_users").fetchone()[0]


def create_user(username: str, password_hash: str, role: str) -> dict[str, Any]:
    user = {
        "id": str(uuid4()),
        "username": username,
        "password_hash": password_hash,
        "role": role,
        "active": 1,
        "created_at": datetime.now(UTC).isoformat(),
    }
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT INTO security_users VALUES (?, ?, ?, ?, ?, ?)", tuple(user.values())
        )
        connection.commit()
    return {key: value for key, value in user.items() if key != "password_hash"}


def get_user(username: str) -> dict[str, Any] | None:
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT * FROM security_users WHERE username=?", (username,)
        ).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, username, role, active, created_at FROM security_users ORDER BY username"
        ).fetchall()
    return [dict(row) for row in rows]


def update_user(username: str, role: str, active: bool) -> bool:
    with closing(_connect()) as connection:
        cursor = connection.execute(
            "UPDATE security_users SET role=?, active=? WHERE username=?",
            (role, int(active), username),
        )
        connection.commit()
        return cursor.rowcount == 1


def create_response_plan(investigation_id: str, actions: list[dict[str, Any]]) -> dict[str, Any]:
    plan = {
        "id": str(uuid4()),
        "investigation_id": investigation_id,
        "actions": actions,
        "status": "待审批",
        "proposed_at": datetime.now(UTC).isoformat(),
        "decided_by": None,
        "decided_at": None,
        "results": [],
    }
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO response_plans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                plan["id"],
                investigation_id,
                json.dumps(actions, ensure_ascii=False),
                plan["status"],
                plan["proposed_at"],
                None,
                None,
                "[]",
            ),
        )
        connection.commit()
    return get_response_plan(investigation_id) or plan


def get_response_plan(investigation_id: str) -> dict[str, Any] | None:
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT * FROM response_plans WHERE investigation_id=?", (investigation_id,)
        ).fetchone()
    if not row:
        return None
    return {
        **{
            key: row[key]
            for key in (
                "id",
                "investigation_id",
                "status",
                "proposed_at",
                "decided_by",
                "decided_at",
            )
        },
        "actions": json.loads(row["actions_json"]),
        "results": json.loads(row["results_json"]),
    }


def decide_response_plan(
    investigation_id: str, actor: str, status: str, results: list[dict[str, Any]]
) -> bool:
    with closing(_connect()) as connection:
        cursor = connection.execute(
            "UPDATE response_plans SET status=?, decided_by=?, decided_at=?, results_json=? "
            "WHERE investigation_id=? AND status='待审批'",
            (
                status,
                actor,
                datetime.now(UTC).isoformat(),
                json.dumps(results, ensure_ascii=False),
                investigation_id,
            ),
        )
        connection.commit()
        return cursor.rowcount == 1


def append_trace(
    investigation_id: str,
    node: str,
    event_type: str,
    input_data: dict[str, Any],
    output_data: dict[str, Any],
) -> None:
    with closing(_connect()) as connection:
        sequence = connection.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM agent_trace WHERE investigation_id=?",
            (investigation_id,),
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO agent_trace VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid4()),
                investigation_id,
                sequence,
                node,
                event_type,
                json.dumps(input_data, ensure_ascii=False),
                json.dumps(output_data, ensure_ascii=False),
                datetime.now(UTC).isoformat(),
            ),
        )
        connection.commit()


POLICY_DEFAULTS: dict[str, int | bool] = {
    "ssh_failed_threshold": 100,
    "port_scan_threshold": 20,
    "simulate_block_ip": True,
    "simulate_ticket": True,
}


def get_security_policy() -> dict[str, int | bool]:
    policy = POLICY_DEFAULTS.copy()
    with closing(_connect()) as connection:
        rows = connection.execute("SELECT key, value_json FROM security_policy").fetchall()
    for row in rows:
        if row["key"] in policy:
            policy[row["key"]] = json.loads(row["value_json"])
    return policy


def update_security_policy(changes: dict[str, int | bool], actor: str) -> dict[str, int | bool]:
    if not changes or set(changes) - set(POLICY_DEFAULTS):
        raise ValueError("没有可更新的策略字段")
    with closing(_connect()) as connection:
        connection.executemany(
            "INSERT INTO security_policy VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, "
            "updated_by=excluded.updated_by, updated_at=excluded.updated_at",
            [
                (key, json.dumps(value), actor, datetime.now(UTC).isoformat())
                for key, value in changes.items()
            ],
        )
        connection.commit()
    return get_security_policy()
