"""用可解释的固定阈值检测模拟安全告警。"""

from security.repository import get_security_policy
from security.siem.schema import SecurityAlert, SecurityEvent


def detect(event: SecurityEvent) -> SecurityAlert | None:
    policy = get_security_policy()
    data = event.raw_data
    count = data.get("count", 0)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return None
    checks = {
        "SSH_FAILED_LOGIN": (
            count >= policy["ssh_failed_threshold"],
            "BRUTE_FORCE",
            "HIGH",
            f"SSH 失败登录达到 {policy['ssh_failed_threshold']} 次",
        ),
        "PORT_SCAN": (
            count >= policy["port_scan_threshold"],
            "PORT_SCAN",
            "MEDIUM",
            f"端口扫描记录达到 {policy['port_scan_threshold']} 次",
        ),
        "PRIVILEGE_ESCALATION": (
            data.get("method") == "sudo",
            "PRIVILEGE_ESCALATION",
            "HIGH",
            "发现异常 sudo 提权事件",
        ),
        "COMMAND_EXECUTION": (
            data.get("interpreter") in {"bash", "sh", "powershell", "cmd"},
            "COMMAND_EXECUTION",
            "HIGH",
            "发现需要核查的命令解释器执行事件",
        ),
        "MALWARE": (
            data.get("signature") == "DEMO-MALWARE",
            "MALWARE",
            "HIGH",
            "命中演示恶意文件特征",
        ),
    }
    matched, alert_type, severity, reason = checks[event.event_type]
    if not matched:
        return None
    return SecurityAlert(
        event_id=event.event_id,
        asset_ip=event.asset_ip,
        alert_type=alert_type,
        severity=severity,
        reason=reason,
    )
