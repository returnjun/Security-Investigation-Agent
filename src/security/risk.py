"""基于证据的可解释风险评分和报告骨架。"""

from datetime import datetime
from typing import Any

from security.repository import get_security_policy
from security.state import SecurityState


def _attack(state: SecurityState, key: str) -> dict[str, Any]:
    technique = state.get("attack_mappings", {}).get(key)
    return {"attack": technique} if technique else {}


def assess_risk(state: SecurityState) -> tuple[str, int, list[dict[str, Any]], list[str]]:
    asset = state.get("asset_info") or {}
    if not state.get("asset_ip") or not asset:
        knowledge = state.get("knowledge") or []
        knowledge_advice = (
            "根据参考知识核对该 CVE 的修复方案与供应商公告，再结合实际安装版本安排更新。"
            if state.get("cve_id")
            else "参考知识可用于分析与缓解建议；应用到具体环境前请核对来源并人工验证。"
        )
        asset_advice = (
            "若需判断具体主机是否受影响，请提供资产 IP、实际组件版本和相关日志。"
            if state.get("cve_id")
            else "若需评估具体主机，请提供资产 IP 和对应时段的安全日志。"
        )
        detail = (
            "已检索到相关安全知识；本次未调查具体主机，资产风险不作判断。"
            if knowledge and not state.get("asset_ip")
            else "已检索到相关安全知识，但没有目标资产的可验证证据，不能判断该主机的实际风险。"
            if knowledge
            else state.get("intent_error") or "未找到可验证的目标资产。"
        )
        return (
            "待确认",
            0,
            [
                {
                    "title": "安全知识参考"
                    if knowledge and not state.get("asset_ip")
                    else "知识参考，资产风险待确认"
                    if knowledge
                    else "资产信息不足",
                    "severity": "未知",
                    "detail": detail,
                    "evidence_ids": [item["id"] for item in knowledge],
                }
            ],
            [knowledge_advice, asset_advice]
            if knowledge
            else ["若需分析具体主机，请提供资产 IP、实际组件版本和相关日志。"],
        )

    if state.get("cve_id") and not any(
        item["id"].upper() == state["cve_id"] for item in state.get("vulnerabilities", [])
    ):
        return (
            "待确认",
            0,
            [
                {
                    "title": "资产与目标 CVE 的关联未证实",
                    "severity": "未知",
                    "detail": f"演示资产库没有 {state['cve_id']} 与该主机的关联记录，不能根据通用知识判定受影响。",
                    "evidence_ids": [item["id"] for item in state.get("knowledge", [])],
                }
            ],
            ["核对目标主机实际安装包版本与发行版安全公告，再判断该 CVE 是否适用。"],
        )

    if state.get("log_scope_note") and not state.get("logs"):
        return (
            "待确认",
            0,
            [
                {
                    "title": "指定时段缺少日志",
                    "severity": "未知",
                    "detail": state["log_scope_note"],
                    "evidence_ids": [],
                }
            ],
            ["补充指定时间范围的真实身份验证与主机审计日志后再判断。"],
        )

    if not any(
        task in state.get("completed_tasks", []) for task in ("log_analysis", "vulnerability_check")
    ):
        return (
            "待确认",
            0,
            [
                {
                    "title": "尚未开展安全检查",
                    "severity": "未知",
                    "detail": "已取得资产信息，但本次计划没有查询安全日志或漏洞记录，不能据此判断资产风险。",
                    "evidence_ids": [f"ASSET-{asset['ip']}"],
                }
            ],
            ["如需评估攻击风险，请进一步查询对应时段的安全日志和漏洞记录。"],
        )

    logs = state.get("logs") or []
    vulnerabilities = state.get("vulnerabilities") or []
    threats = state.get("threat_info") or []
    findings: list[dict[str, Any]] = []
    recommendations: list[str] = []
    score = 0
    policy = get_security_policy()

    failed = [item for item in logs if item["event"] == "SSH 登录失败"]
    failed_count = sum(item["event_count"] for item in failed)
    if failed_count >= policy["ssh_failed_threshold"]:
        score += 55 if failed_count >= max(500, policy["ssh_failed_threshold"] * 5) else 35
        findings.append(
            {
                "title": "疑似 SSH 暴力破解",
                "severity": "高",
                "detail": f"演示日志中记录 {failed_count} 次失败登录。",
                "evidence_ids": [item["id"] for item in failed],
                **_attack(state, "ssh_brute_force"),
            }
        )
        recommendations.append("核查 SSH 失败登录来源，限制尝试频率并启用多因素认证。")

    later_success = [
        item
        for item in logs
        if item["event"] == "SSH 登录成功"
        and any(
            prior["source_ip"] == item["source_ip"]
            and datetime.fromisoformat(prior["time"]) < datetime.fromisoformat(item["time"])
            for prior in failed
        )
    ]
    if later_success:
        score += 25
        findings.append(
            {
                "title": "失败尝试后出现同源登录成功",
                "severity": "高",
                "detail": "同一来源既有大量失败登录，也出现成功登录，需要核对账号与时间线。",
                "evidence_ids": [item["id"] for item in failed + later_success],
            }
        )
        recommendations.append("核对成功登录的账号、会话和变更记录，必要时轮换凭据。")

    escalation = [item for item in logs if item["event"] == "异常提权"]
    if escalation:
        score += 70
        findings.append(
            {
                "title": "检测到异常提权",
                "severity": "高",
                "detail": "演示日志存在异常权限提升事件。",
                "evidence_ids": [item["id"] for item in escalation],
                **_attack(state, "privilege_escalation"),
            }
        )
        recommendations.append("核查提权命令、账号权限与主机完整性，保留相关审计日志。")

    scans = [
        item
        for item in logs
        if item["event"] == "端口扫描" and item["event_count"] >= policy["port_scan_threshold"]
    ]
    if scans:
        score += 35
        findings.append(
            {
                "title": "检测到端口扫描线索",
                "severity": "中",
                "detail": "演示日志记录了达到告警阈值的端口扫描行为，需核对来源与业务背景。",
                "evidence_ids": [item["id"] for item in scans],
            }
        )
        recommendations.append("核对扫描来源、授权测试计划和目标服务暴露面。")

    commands = [item for item in logs if item["event"] == "命令解释器执行"]
    if commands:
        score += 35
        findings.append(
            {
                "title": "需要核查的命令解释器执行",
                "severity": "中",
                "detail": "演示事件记录了命令解释器执行；仅凭这一事件不能认定命令恶意。",
                "evidence_ids": [item["id"] for item in commands],
                **_attack(state, "command_execution"),
            }
        )
        recommendations.append("核查执行账号、进程关系、命令内容和变更记录。")

    malware = [item for item in logs if item["event"] == "恶意文件告警"]
    if malware:
        score += 70
        findings.append(
            {
                "title": "演示恶意文件特征告警",
                "severity": "高",
                "detail": "模拟 SIEM 命中演示特征；需要复核文件哈希、路径与检测上下文。",
                "evidence_ids": [item["id"] for item in malware],
            }
        )
        recommendations.append("保留文件与进程证据，由安全人员核验告警真实性。")

    high_vulns = [item for item in vulnerabilities if item["severity"] == "高"]
    medium_vulns = [item for item in vulnerabilities if item["severity"] == "中"]
    if high_vulns or medium_vulns:
        score += 25 if high_vulns else 10
        findings.append(
            {
                "title": "资产存在待修复配置或组件问题",
                "severity": "高" if high_vulns else "中",
                "detail": "演示漏洞库记录了与该资产关联的问题。",
                "evidence_ids": [item["id"] for item in vulnerabilities],
            }
        )
        recommendations.extend(item["solution"] for item in vulnerabilities)

    suspicious = [item for item in threats if item["score"] >= 70]
    if suspicious:
        score += 20
        findings.append(
            {
                "title": "来源 IP 信誉异常",
                "severity": "中",
                "detail": "与日志关联的来源 IP 在演示情报库中被标记为可疑。",
                "evidence_ids": [f"THREAT-{item['ip']}" for item in suspicious],
            }
        )
        recommendations.append("结合真实威胁情报核验来源 IP，再决定是否采取阻断措施。")

    if score and asset.get("importance") == "高":
        score += 5
    history = state.get("history") or []
    if score and len(history) >= 3:
        history_bonus = 10
        recent = [item["risk_score"] for item in history[-3:]]
        rising = recent[0] < recent[1] < recent[2]
        if rising:
            history_bonus += 15
        score += history_bonus
        findings.append(
            {
                "title": "资产近期持续出现风险" if not rising else "资产近期风险持续上升",
                "severity": "中" if not rising else "高",
                "detail": (
                    f"近7天已有 {len(history)} 次历史调查；最近三次评分为 "
                    f"{' → '.join(str(value) for value in recent)}，历史因素增加 {history_bonus} 分。"
                ),
                "evidence_ids": [f"HIST-{item['investigation_id']}" for item in history[-3:]],
            }
        )
        recommendations.append("复核历次调查与反馈，确认异常是否持续并排除重复告警。")
    score = min(score, 100)
    level = "高" if score >= 70 else "中" if score >= 35 else "低"
    if not findings:
        findings.append(
            {
                "title": "演示证据未显示明显异常",
                "severity": "低",
                "detail": "当前模拟数据中没有命中高风险规则。",
                "evidence_ids": [],
            }
        )
        recommendations.append("继续监控资产；该结论仅基于演示数据，不能替代真实安全审计。")
    return level, score, findings, list(dict.fromkeys(recommendations))


def render_report(state: SecurityState, analysis: str) -> str:
    level = state["risk_level"]
    score = state["risk_score"]
    asset_ip = state.get("asset_ip") or state.get("cve_id") or "知识问答"
    asset = state.get("asset_info") or {}
    findings = state["findings"]
    recommendations = state["recommendations"]
    lines = [
        "# 安全事件调查报告",
        "",
        f"**目标资产：** {asset_ip}  ",
        f"**资产名称：** {asset.get('hostname', '不适用' if not state.get('asset_ip') else '未找到')}  ",
        f"**风险等级：** {level}（规则评分 {score}/100）  ",
        "**数据范围：** 资产、日志与信誉为本地合成演示数据；安全知识为带来源的本地文档。不能用于真实处置决策。",
        f"**调查计划：** {' → '.join(state.get('investigation_plan', [])) or '未生成'}",
        f"**近7天历史调查：** {len(state.get('history') or [])} 次",
        "",
        "## 调查发现",
    ]
    for index, finding in enumerate(findings, 1):
        refs = "、".join(finding["evidence_ids"]) or "无"
        attack = finding.get("attack")
        technique = f"；ATT&CK {attack['id']}（{attack['name']}）" if attack else ""
        lines.append(
            f"{index}. **{finding['title']}**：{finding['detail']}（证据：{refs}{technique}）"
        )
    lines.extend(["", "## 综合分析", analysis, "", "## 建议措施"])
    lines.extend(f"{index}. {item}" for index, item in enumerate(recommendations, 1))
    matches = state.get("mitre_matches") or []
    if matches:
        lines.extend(["", "## MITRE ATT&CK 技术映射"])
        lines.extend(
            f"- [{item['id']} · {item['name']}]({item['source_url']})：{item['tactic']}"
            for item in matches
        )
        lines.append("技术映射表示日志行为与技术描述相符，不代表已确认攻击者、入侵成功或攻击归因。")
    knowledge = state.get("knowledge") or []
    if knowledge:
        lines.extend(["", "## 参考知识"])
        lines.extend(
            f"- [{item['title'] if item['title'].startswith(item['id']) else item['id'] + '：' + item['title']}]({item['source_url']})"
            for item in knowledge
        )
    elif "security_rag" in state.get("completed_tasks", []):
        lines.extend(["", "## 参考知识", "本地知识库未检索到与问题匹配的资料。"])
    lines.extend(
        [
            "",
            "## 人工确认",
            "任何封禁 IP、隔离主机或修改生产配置的动作均需安全人员核实证据后批准；本版本不会自动执行响应动作。",
        ]
    )
    return "\n".join(lines)
