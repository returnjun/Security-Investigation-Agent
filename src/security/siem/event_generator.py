"""只生成合成事件记录，不执行任何网络探测或攻击。"""

from ipaddress import IPv4Address

from security.siem.schema import EventType, SecurityEvent

SCENARIOS: dict[EventType, tuple[str, dict[str, str | int]]] = {
    "SSH_FAILED_LOGIN": ("HIGH", {"source_ip": "203.0.113.45", "count": 500}),
    "PORT_SCAN": ("MEDIUM", {"source_ip": "203.0.113.45", "count": 80}),
    "PRIVILEGE_ESCALATION": (
        "HIGH",
        {"source_ip": "198.51.100.77", "count": 1, "method": "sudo"},
    ),
    "COMMAND_EXECUTION": (
        "HIGH",
        {"source_ip": "198.51.100.77", "count": 1, "interpreter": "bash"},
    ),
    "MALWARE": (
        "HIGH",
        {"source_ip": "198.51.100.77", "count": 1, "signature": "DEMO-MALWARE"},
    ),
}


def generate_event(scenario: EventType, asset_ip: IPv4Address) -> SecurityEvent:
    severity, raw_data = SCENARIOS[scenario]
    return SecurityEvent(
        source="合成攻击事件模拟器",
        asset_ip=asset_ip,
        event_type=scenario,
        severity=severity,
        raw_data=raw_data.copy(),
    )
