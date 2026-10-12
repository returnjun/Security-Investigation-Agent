"""安全事件调查工作台：围绕一次调查呈现流程、证据和报告。"""

import html
import json
import os
from datetime import datetime
from typing import Any

import httpx
import streamlit as st

STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Noto+Sans+SC:wght@400;500;600;700&display=swap');
html, body, [class*="css"], [data-testid="stApp"] {
    font-family: 'DM Sans', 'Noto Sans SC', sans-serif;
}
[data-testid="stAppViewContainer"] { background: #f5f7f7; color: #19313c; }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stMainBlockContainer"] { max-width: 1180px; padding-top: 2.6rem; padding-bottom: 5rem; }
[data-testid="stSidebar"] { background: #102b35; }
[data-testid="stSidebar"] * { color: #e8f2f0 !important; }
[data-testid="stSidebar"] button { border-color: #48646b !important; background: #183844 !important; }
[data-testid="stSidebar"] button:hover { border-color: #68c6ae !important; }
.stButton button[kind="primary"] { background: #126e63; border: 1px solid #126e63; color: white; border-radius: 10px; font-weight: 600; min-height: 3rem; }
.stButton button[kind="primary"]:hover { background: #0f5c54; border-color: #0f5c54; color: white; }
.stButton button[kind="secondary"] { border-radius: 10px; border-color: #d9e3e2; background: white; color: #28434b; }
textarea, input { border-radius: 10px !important; }
.hero { padding: 2.1rem 2.35rem; border-radius: 20px; background: linear-gradient(110deg, #102e38 0%, #1a4b50 75%, #2e6a63 100%); color: white; margin-bottom: 2rem; box-shadow: 0 16px 40px rgba(16, 46, 56, .12); }
.eyebrow { letter-spacing: .16em; font-size: .72rem; font-weight: 700; color: #83d8c5; }
.hero h1 { color: white; letter-spacing: -.035em; font-size: 2.2rem; line-height: 1.35; margin: .7rem 0 .6rem; }
.hero p { color: #d3e6e3; max-width: 690px; font-size: .99rem; margin: 0; line-height: 1.8; }
.section-heading { margin: 1.2rem 0 .7rem; font-size: 1.16rem; font-weight: 700; color: #19313c; }
.muted { color: #668087; font-size: .9rem; }
.badge { display: inline-block; border: 1px solid #d2e5e0; background: #e9f5f1; color: #126e63; padding: .3rem .65rem; border-radius: 100px; font-size: .75rem; font-weight: 700; }
.info-strip { padding: .82rem 1rem; background: #eaf3f1; border: 1px solid #d8e9e5; color: #335b5d; border-radius: 10px; margin-bottom: 1.4rem; font-size: .85rem; }
.data-card { background: white; border: 1px solid #e1e9e9; border-radius: 15px; padding: 1.15rem 1.25rem; min-height: 105px; box-shadow: 0 3px 15px rgba(18, 54, 61, .025); }
.data-card .label { color: #72878d; font-size: .78rem; margin-bottom: .38rem; }
.data-card .value { color: #19313c; font-size: 1.38rem; font-weight: 700; line-height: 1.3; }
.data-card .sub { color: #789096; font-size: .74rem; margin-top: .25rem; }
.finding-card { background: white; border: 1px solid #e1e9e9; border-left: 4px solid #d68b58; border-radius: 12px; padding: 1rem 1.2rem; margin: .65rem 0; }
.finding-card strong { color: #19313c; font-size: .96rem; }
.finding-card p { color: #546d74; font-size: .86rem; margin: .35rem 0; }
.finding-card small { color: #7f9095; }
.side-brand { padding: .5rem 0 1.1rem; border-bottom: 1px solid #39555c; margin-bottom: 1rem; }
.side-brand .mark { display: inline-block; padding: .43rem .62rem; border: 1px solid #4e9589; border-radius: 9px; color: #87ddcb; font-weight: 700; margin-right: .55rem; }
.side-brand strong { font-size: 1.05rem; }
.side-caption { color: #a7c0c2 !important; font-size: .74rem; letter-spacing: .12em; margin: 1.3rem 0 .45rem; }
.trace-step { position: relative; background: white; border: 1px solid #dde8e7; border-left: 4px solid #1e8778; border-radius: 13px; padding: .9rem 1.1rem; margin: .75rem 0 1.1rem 1.25rem; box-shadow: 0 3px 15px rgba(18, 54, 61, .025); }
.trace-step:before { content: ''; position: absolute; left: -1.15rem; top: 1.35rem; height: .85rem; width: .85rem; background: #1e8778; border: 3px solid #d8eee8; border-radius: 50%; }
.trace-step:after { content: ''; position: absolute; left: -0.78rem; top: 2.2rem; height: calc(100% + .6rem); border-left: 2px solid #cfe3df; }
.trace-step:last-child:after { display: none; }
.trace-step strong { color: #173b41; font-size: .95rem; }
.trace-step p { color: #587177; font-size: .84rem; margin: .3rem 0 0; }
.trace-step small { color: #6f8d90; font-size: .72rem; }
div[data-testid="stExpander"] { background: white; border: 1px solid #e1e9e9; border-radius: 12px; }
</style>
"""


def _base_url() -> str:
    configured = os.getenv("AGENT_URL")
    if configured:
        return configured.rstrip("/")
    host = os.getenv("HOST", "127.0.0.1")
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    return f"http://{host}:{os.getenv('PORT', '8080')}"


def _headers(path: str) -> dict[str, str]:
    if path.startswith("/security/") or path.startswith("/trace/"):
        token = st.session_state.get("security_token")
        return {"Authorization": f"Bearer {token}"} if token else {}
    return {}


def _get(path: str) -> Any:
    response = httpx.get(f"{_base_url()}{path}", headers=_headers(path), timeout=12)
    response.raise_for_status()
    return response.json()


def _post(path: str, payload: dict[str, Any]) -> Any:
    response = httpx.post(f"{_base_url()}{path}", json=payload, headers=_headers(path), timeout=200)
    response.raise_for_status()
    return response.json()


def _patch(path: str, payload: dict[str, Any]) -> Any:
    response = httpx.patch(f"{_base_url()}{path}", json=payload, headers=_headers(path), timeout=12)
    response.raise_for_status()
    return response.json()


def _escape(value: Any) -> str:
    return html.escape(str(value))


def _card(label: str, value: Any, sub: str = "") -> None:
    st.markdown(
        '<div class="data-card">'
        f'<div class="label">{_escape(label)}</div>'
        f'<div class="value">{_escape(value)}</div>'
        f'<div class="sub">{_escape(sub)}</div></div>',
        unsafe_allow_html=True,
    )


def _render_login() -> None:
    st.markdown(
        '<div class="hero"><div class="eyebrow">安全调查工作台</div>'
        "<h1>登录后开始调查。</h1><p>分析员可查看报告并提交反馈；主管可审批模拟响应。</p></div>",
        unsafe_allow_html=True,
    )
    with st.form("security_login"):
        username = st.text_input("用户名")
        password = st.text_input("密码", type="password")
        submitted = st.form_submit_button("登录", type="primary")
    if submitted:
        try:
            data = _post("/security/auth/login", {"username": username, "password": password})
            st.session_state["security_token"] = data["access_token"]
            st.rerun()
        except (httpx.HTTPError, ValueError):
            st.error("登录失败，请核对账号、密码和后端服务。")
    st.info("首次使用：在项目根目录运行 `python scripts/create_security_admin.py` 创建管理员。")


def _render_users() -> None:
    st.markdown('<div class="section-heading">用户管理</div>', unsafe_allow_html=True)
    with st.form("create_security_user"):
        username = st.text_input("新用户名")
        password = st.text_input("初始密码（至少12位）", type="password")
        role = st.selectbox("角色", ["ANALYST", "MANAGER", "ADMIN"])
        create = st.form_submit_button("创建账号")
    if create:
        try:
            _post(
                "/security/auth/users", {"username": username, "password": password, "role": role}
            )
            st.success("账号已创建。")
        except (httpx.HTTPError, ValueError) as exc:
            st.error(f"创建失败：{exc}")
    try:
        users = _get("/security/auth/users")
    except (httpx.HTTPError, ValueError):
        users = []
    st.dataframe(users, hide_index=True, width="stretch")
    if users:
        selected = st.selectbox("调整账号", [item["username"] for item in users])
        current = next(item for item in users if item["username"] == selected)
        with st.form(f"update_security_user_{selected}"):
            roles = ["ANALYST", "MANAGER", "ADMIN"]
            new_role = st.selectbox("新角色", roles, index=roles.index(current["role"]))
            active = st.checkbox("账号启用", value=bool(current["active"]))
            update = st.form_submit_button("保存账号设置")
        if update:
            try:
                _patch(f"/security/auth/users/{selected}", {"role": new_role, "active": active})
                st.success("账号设置已更新。")
                st.rerun()
            except (httpx.HTTPError, ValueError) as exc:
                st.error(f"更新失败：{exc}")
    st.markdown('<div class="section-heading">规则与模拟工具配置</div>', unsafe_allow_html=True)
    try:
        policy = _get("/security/admin/policy")
    except (httpx.HTTPError, ValueError):
        policy = {}
    if policy:
        with st.form("security_policy"):
            ssh = st.number_input(
                "SSH 失败登录告警阈值", 20, 10000, value=policy["ssh_failed_threshold"]
            )
            scan = st.number_input(
                "端口扫描告警阈值", 5, 10000, value=policy["port_scan_threshold"]
            )
            ticket = st.checkbox("允许生成模拟工单建议", value=policy["simulate_ticket"])
            block = st.checkbox("允许生成模拟封禁建议", value=policy["simulate_block_ip"])
            save_policy = st.form_submit_button("保存策略")
        if save_policy:
            try:
                _patch(
                    "/security/admin/policy",
                    {
                        "ssh_failed_threshold": ssh,
                        "port_scan_threshold": scan,
                        "simulate_ticket": ticket,
                        "simulate_block_ip": block,
                    },
                )
                st.success("策略已更新，后续事件将使用新设置。")
                st.rerun()
            except (httpx.HTTPError, ValueError) as exc:
                st.error(f"策略更新失败：{exc}")


def _sidebar(assets: list[dict[str, Any]], history: list[dict[str, Any]], user: dict) -> None:
    with st.sidebar:
        st.markdown(
            '<div class="side-brand"><span class="mark">安</span><strong>安全调查工作台</strong></div>',
            unsafe_allow_html=True,
        )
        st.caption("基于 LangGraph 的安全事件调查演示")
        st.caption(f"当前账号：{user['username']} · {user['role']}")
        st.markdown('<div class="side-caption">工作台</div>', unsafe_allow_html=True)
        if st.button("调查工作台", key="nav_investigation", width="stretch"):
            st.query_params["view"] = "security"
            st.rerun()
        if st.button("模拟 SIEM 与告警", key="nav_siem", width="stretch"):
            st.query_params["view"] = "siem"
            st.rerun()
        if user["role"] == "ADMIN" and st.button("用户管理", key="nav_users", width="stretch"):
            st.query_params["view"] = "users"
            st.rerun()
        st.markdown('<div class="side-caption">演示资产</div>', unsafe_allow_html=True)
        for asset in assets:
            if st.button(
                f"{asset['hostname']}  ·  {asset['ip']}",
                key=f"asset_{asset['ip']}",
                width="stretch",
            ):
                st.session_state["security_query"] = (
                    f"请调查 {asset['ip']} 最近是否有可疑活动，并给出风险评估。"
                )
                st.rerun()

        st.markdown('<div class="side-caption">知识问答示例</div>', unsafe_allow_html=True)
        for name, question in (
            ("SSH 暴力破解怎么处理？", "SSH 暴力破解怎么处理？"),
            ("了解 CVE-2024-6387", "CVE-2024-6387 严重吗？应该如何修复？"),
        ):
            if st.button(name, key=f"example_{name}", width="stretch"):
                st.session_state["security_query"] = question
                st.rerun()

        st.markdown('<div class="side-caption">最近调查</div>', unsafe_allow_html=True)
        if not history:
            st.caption("运行一次调查后，记录会显示在这里。")
        for item in history[:8]:
            time_label = (
                datetime.fromisoformat(item["created_at"]).astimezone().strftime("%m-%d %H:%M:%S")
            )
            label = f"{item['asset_ip'] or '知识问答'}  ·  {time_label}"
            if st.button(label, key=f"history_{item['id']}", width="stretch"):
                try:
                    st.session_state["security_result"] = _get(
                        f"/security/investigations/{item['id']}"
                    )
                    st.rerun()
                except (httpx.HTTPError, ValueError):
                    st.error("读取调查记录失败，请稍后重试。")

        st.divider()
        st.caption("所有资产、日志、漏洞和情报均为合成演示数据。")
        if st.button("退出安全工作台", width="stretch"):
            st.session_state.pop("security_token", None)
            st.query_params["view"] = "security"
            st.rerun()


def _run_investigation(query: str, model: str) -> None:
    labels = {
        "intent_analyzer": "识别调查目标",
        "planner_agent": "规划调查任务",
        "executor": "选择下一项任务",
        "asset_agent": "读取资产资料",
        "history_agent": "读取资产历史",
        "log_agent": "检索安全日志",
        "vulnerability_agent": "核查漏洞记录",
        "threat_agent": "核验来源 IP 信誉",
        "rag_agent": "检索安全知识",
        "evidence_collector": "汇总证据并判断下一步",
        "mitre_mapper": "映射 MITRE ATT&CK 技术",
        "risk_agent": "完成规则风险评估",
        "report_agent": "完成综合报告",
    }
    st.session_state.pop("security_result", None)
    try:
        with st.status("正在规划并执行调查…", expanded=True) as status:
            with httpx.stream(
                "POST",
                f"{_base_url()}/security/investigate/stream",
                json={"query": query, "model": model},
                headers=_headers("/security/investigate/stream"),
                timeout=200,
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line.startswith("data: "):
                        continue
                    event = json.loads(line[6:])
                    if event["type"] == "step":
                        st.write(f"✓ {labels.get(event['node'], event.get('label', '处理完成'))}")
                    elif event["type"] == "result":
                        st.session_state["security_result"] = event["data"]
                    elif event["type"] == "error":
                        raise RuntimeError(event.get("message", "调查失败"))
            if "security_result" not in st.session_state:
                raise RuntimeError("服务未返回调查报告。")
            status.update(label="调查完成", state="complete", expanded=False)
    except (httpx.HTTPError, ValueError, RuntimeError) as exc:
        st.error(f"调查未完成：{exc}")


def _show_result(result: dict[str, Any]) -> None:
    task_labels = {
        "asset_check": "资产查询",
        "asset_history_check": "资产历史",
        "log_analysis": "日志分析",
        "vulnerability_check": "漏洞查询",
        "threat_check": "来源信誉",
        "security_rag": "安全知识检索",
    }
    st.markdown('<div class="section-heading">调查概览</div>', unsafe_allow_html=True)
    asset = result.get("asset_info") or {}
    cols = st.columns(4, gap="medium")
    with cols[0]:
        _card("风险等级", result["risk_level"], f"规则评分 {result['risk_score']}/100")
    with cols[1]:
        target = result.get("asset_ip") or result.get("cve_id") or "知识问答"
        _card("调查目标", target, asset.get("hostname", ""))
    with cols[2]:
        _card("关联日志", len(result.get("logs", [])), "条演示记录")
    with cols[3]:
        _card("调查发现", len(result.get("findings", [])), "项可追溯结论")

    plan = result.get("investigation_plan") or []
    if plan:
        st.markdown('<div class="section-heading">调查计划</div>', unsafe_allow_html=True)
        st.markdown(" → ".join(task_labels.get(task, task) for task in plan))
        st.caption(f"{result.get('planner_mode', '规划')} · {result.get('plan_reason', '')}")
        with st.expander("查看任务执行轨迹", expanded=False):
            for event in result.get("execution_trace", []):
                st.write(f"• {event}")

    history = result.get("history") or []
    if result.get("asset_ip"):
        st.markdown(
            '<div class="section-heading">近 7 天资产调查历史</div>', unsafe_allow_html=True
        )
        if history:
            st.dataframe(
                [
                    {
                        "时间": item["created_at"],
                        "风险等级": item["risk_level"],
                        "评分": item["risk_score"],
                        "人工反馈": "、".join(item.get("feedback_labels", [])) or "暂无",
                        "调查编号": item["investigation_id"],
                    }
                    for item in history
                ],
                hide_index=True,
                width="stretch",
            )
        else:
            st.caption("此前没有该资产的调查记录。")

    st.markdown('<div class="section-heading">调查发现</div>', unsafe_allow_html=True)
    for finding in result.get("findings", []):
        refs = " · ".join(finding.get("evidence_ids", [])) or "暂无证据编号"
        st.markdown(
            '<div class="finding-card">'
            f"<strong>{_escape(finding['title'])}</strong>"
            f"<p>{_escape(finding['detail'])}</p>"
            f"<small>证据：{_escape(refs)}</small></div>",
            unsafe_allow_html=True,
        )

    st.markdown('<div class="section-heading">综合分析</div>', unsafe_allow_html=True)
    st.write(result.get("analysis", ""))
    if result.get("log_scope_note"):
        st.info(result["log_scope_note"])
    knowledge = result.get("knowledge") or []
    if knowledge:
        st.markdown('<div class="section-heading">参考知识</div>', unsafe_allow_html=True)
        st.caption(result.get("retrieval_mode", ""))
        for item in knowledge:
            with st.expander(f"{item['id']} · {item['title']}"):
                st.write(item["content"])
                st.markdown(f"[查看来源]({item['source_url']})")
    elif "security_rag" in result.get("completed_tasks", []):
        st.info("本地知识库没有找到与该问题匹配的资料。")
    matches = result.get("mitre_matches") or []
    if matches:
        st.markdown(
            '<div class="section-heading">MITRE ATT&CK 技术映射</div>', unsafe_allow_html=True
        )
        for item in matches:
            st.markdown(
                f"**[{item['id']} · {item['name']}]({item['source_url']})** · {item['tactic']}"
            )
        st.caption("映射表示行为特征相符，不代表已确认入侵或攻击归因。")
    with st.expander("查看原始证据", expanded=False):
        for title, key in (
            ("资产信息", "asset_info"),
            ("安全日志", "logs"),
            ("漏洞记录", "vulnerabilities"),
            ("IP 信誉", "threat_info"),
            ("证据索引", "evidence"),
        ):
            st.markdown(f"**{title}**")
            data = result.get(key) or ([] if key != "asset_info" else {})
            if isinstance(data, list) and data:
                st.dataframe(data, width="stretch", hide_index=True)
            elif isinstance(data, dict) and data:
                st.json(data, expanded=False)
            else:
                st.caption("无记录")

    st.markdown('<div class="section-heading">完整调查报告</div>', unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown(result["report"])
    investigation_id = result.get("id")
    if investigation_id:
        st.markdown('<div class="section-heading">人工反馈</div>', unsafe_allow_html=True)
        with st.form(f"feedback_{investigation_id}"):
            label = st.radio(
                "本次分析是否准确？",
                ["correct", "false_positive", "needs_revision"],
                format_func=lambda item: {
                    "correct": "正确",
                    "false_positive": "误报",
                    "needs_revision": "需要调整",
                }[item],
                horizontal=True,
            )
            comment = st.text_area("补充说明", max_chars=1000)
            submitted = st.form_submit_button("提交反馈")
        if submitted:
            try:
                _post(
                    "/security/feedback",
                    {"investigation_id": investigation_id, "label": label, "comment": comment},
                )
                st.success("反馈已保存，供后续人工优化规则和知识库。")
            except (httpx.HTTPError, ValueError) as exc:
                st.error(f"保存反馈失败：{exc}")
        try:
            response_plan = _get(f"/security/investigations/{investigation_id}/response")
        except (httpx.HTTPError, ValueError):
            response_plan = None
        if response_plan:
            st.markdown('<div class="section-heading">响应建议与审批</div>', unsafe_allow_html=True)
            st.caption(f"状态：{response_plan['status']}。所有动作仅为本地模拟。")
            for action in response_plan["actions"]:
                st.write(f"• {action['type']} · {action['target']}：{action['reason']}")
            if response_plan["status"] == "待审批" and st.session_state.get(
                "security_user", {}
            ).get("role") in {"MANAGER", "ADMIN"}:
                left, right = st.columns(2)
                decision = None
                with left:
                    if st.button("批准模拟执行", key=f"approve_{investigation_id}"):
                        decision = True
                with right:
                    if st.button("拒绝方案", key=f"reject_{investigation_id}"):
                        decision = False
                if decision is not None:
                    try:
                        _post(
                            f"/security/investigations/{investigation_id}/response/decision",
                            {"approved": decision},
                        )
                        st.rerun()
                    except (httpx.HTTPError, ValueError) as exc:
                        st.error(f"审批失败：{exc}")
            for item in response_plan.get("results") or []:
                st.success(item["message"])
    if result.get("id") and st.button("查看完整执行轨迹  →", key="open_trace", width="stretch"):
        st.query_params["view"] = "trace"
        st.query_params["investigation_id"] = result["id"]
        st.rerun()
    st.download_button(
        "下载 Markdown 报告",
        data=result["report"],
        file_name=f"安全调查_{result.get('asset_ip') or result.get('cve_id') or '知识问答'}.md",
        mime="text/markdown",
        width="content",
    )


def _trace_summary(entry: dict[str, Any]) -> str:
    output = entry.get("output") or {}
    node = entry["node_name"]
    if node == "planner_agent":
        return "选择任务：" + " → ".join(output.get("investigation_plan") or [])
    if node == "log_agent":
        events = output.get("events") or []
        return (
            "发现：" + "、".join(f"{item['type']} {item['count']} 次" for item in events)
            if events
            else "未找到匹配日志"
        )
    if node == "evidence_collector":
        return f"累计 {len(output.get('evidence_ids') or [])} 条证据；待执行计划已更新"
    if node == "mitre_mapper":
        return (
            "技术映射：" + "、".join(output.get("technique_ids") or [])
            if output.get("technique_ids")
            else "未形成有证据支持的技术映射"
        )
    if node == "risk_agent":
        return f"规则评分 {output.get('risk_score', 0)}/100，风险等级 {output.get('risk_level', '待确认')}"
    if node == "alert_detector":
        return f"{output.get('reason', '未命中告警')} · {output.get('alert_id', '')}"
    if node == "report_agent":
        return "调查报告已生成" if output.get("report_ready") else "报告生成未完成"
    if node == "executor":
        return f"下一任务：{output.get('current_task') or '进入风险评估'}"
    ids = output.get("evidence_ids") or []
    if ids:
        return "证据：" + "、".join(ids)
    if node == "siem_collector":
        return f"事件 {output.get('event_type')} 已进入事件库"
    return "节点执行完成"


def _render_trace_page(investigation_id: str) -> None:
    if st.button("← 返回调查工作台", key="trace_back"):
        st.query_params["view"] = "security"
        st.rerun()
    if not investigation_id:
        st.info("请先选择一条调查记录。")
        return
    try:
        result = _get(f"/security/investigations/{investigation_id}")
        trace = _get(f"/security/investigations/{investigation_id}/trace")
    except (httpx.HTTPError, ValueError):
        st.error("无法读取这次调查的执行轨迹。")
        return
    st.markdown(
        '<div class="hero"><div class="eyebrow">调查执行轨迹</div>'
        "<h1>每一步，都能回看。</h1>"
        "<p>按实际运行顺序展示事件采集、任务规划、证据收集、技术映射和规则报告。</p></div>",
        unsafe_allow_html=True,
    )
    st.caption(f"调查编号：{investigation_id} · {result['query']}")
    summary = st.columns(3, gap="medium")
    with summary[0]:
        _card("节点数", len(trace), "按执行顺序记录")
    with summary[1]:
        _card("风险等级", result["risk_level"], f"评分 {result['risk_score']}/100")
    with summary[2]:
        _card("证据数量", len(result.get("evidence") or []), "可在调查报告中查看")
    st.markdown('<div class="section-heading">调查流程</div>', unsafe_allow_html=True)
    if not trace:
        st.info("这条记录创建于 V3 轨迹功能启用前，没有节点轨迹。")
    for entry in trace:
        label = {
            "siem_collector": "SIEM 事件采集",
            "alert_detector": "告警规则检测",
            "intent_analyzer": "识别目标",
            "planner_agent": "Planner 规划",
            "executor": "Executor 调度",
            "asset_agent": "资产查询",
            "history_agent": "资产历史",
            "response_planner": "生成响应建议",
            "human_approval": "人工审批",
            "response_tool": "模拟执行",
            "log_agent": "日志分析",
            "vulnerability_agent": "漏洞查询",
            "threat_agent": "来源信誉核验",
            "rag_agent": "安全知识检索",
            "evidence_collector": "证据汇总",
            "mitre_mapper": "MITRE 技术映射",
            "risk_agent": "规则风险评估",
            "report_agent": "报告生成",
        }.get(entry["node_name"], entry["node_name"])
        st.markdown(
            '<div class="trace-step">'
            f"<small>第 {entry['sequence']:02d} 步 · {_escape(entry['event_type'])}</small><br>"
            f"<strong>{_escape(label)}</strong><p>{_escape(_trace_summary(entry))}</p></div>",
            unsafe_allow_html=True,
        )
        with st.expander(f"查看第 {entry['sequence']} 步输入与输出摘要"):
            st.json({"输入摘要": entry["input"], "输出摘要": entry["output"]}, expanded=False)


def _render_siem_page(assets: list[dict[str, Any]], service_info: dict[str, Any]) -> None:
    st.markdown(
        '<div class="hero"><div class="eyebrow">模拟 SIEM / 事件驱动调查</div>'
        "<h1>让告警，自动进入调查。</h1>"
        "<p>生成一条合成安全事件；确定性规则命中后，Planner 会启动调查并保留完整执行轨迹。</p></div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="info-strip">这里仅生成数据库事件，不会对任何主机执行扫描、登录或处置。</div>',
        unsafe_allow_html=True,
    )
    names = {
        "SSH_FAILED_LOGIN": "SSH 失败登录（500 次）",
        "PORT_SCAN": "端口扫描（80 次）",
        "PRIVILEGE_ESCALATION": "sudo 提权事件",
        "COMMAND_EXECUTION": "命令解释器执行",
        "MALWARE": "恶意文件特征告警",
    }
    st.markdown('<div class="section-heading">生成演示事件</div>', unsafe_allow_html=True)
    first, second, third = st.columns([1.7, 1.3, 1.4])
    with first:
        scenario = st.selectbox("事件场景", list(names), format_func=lambda item: names[item])
    with second:
        asset_ip = st.selectbox("目标资产", [item["ip"] for item in assets]) if assets else None
    with third:
        available = service_info.get("models", [])
        preferred = ["gpt-4o-mini", "gpt-5.4-mini", "deepseek-reasoner"]
        choices = [name for name in preferred if name in available]
        choices.extend(name for name in available if name not in choices)
        model = st.selectbox("规划模型", choices or ["gpt-4o-mini"])
    if st.button("生成事件并自动调查  →", type="primary", disabled=not asset_ip):
        try:
            with st.spinner("正在采集事件、检测告警并运行调查…"):
                data = _post(
                    "/security/siem/simulate",
                    {"scenario": scenario, "asset_ip": asset_ip, "model": model},
                )
            st.session_state["siem_result"] = data
        except (httpx.HTTPError, ValueError) as exc:
            st.error(f"模拟事件未能完成：{exc}")
    current = st.session_state.get("siem_result")
    if current:
        st.success(f"事件 {current['event']['event_id']} 已采集。")
        if current.get("alert"):
            st.write(f"告警：**{current['alert']['alert_type']}** · {current['alert']['reason']}")
        investigation = current.get("investigation")
        if investigation:
            cols = st.columns(3, gap="medium")
            with cols[0]:
                _card("风险等级", investigation["risk_level"], f"{investigation['risk_score']}/100")
            with cols[1]:
                _card(
                    "执行任务", len(investigation.get("completed_tasks") or []), "Planner 动态选择"
                )
            with cols[2]:
                _card("轨迹节点", len(investigation.get("trace") or []), "含采集与检测")
            if st.button("查看本次调查报告", key="siem_report"):
                st.session_state["security_result"] = investigation
                st.query_params["view"] = "security"
                st.rerun()
            if st.button("查看本次执行轨迹", key="siem_trace"):
                st.query_params["view"] = "trace"
                st.query_params["investigation_id"] = investigation["id"]
                st.rerun()
    st.markdown('<div class="section-heading">最近告警</div>', unsafe_allow_html=True)
    try:
        alerts = _get("/security/siem/alerts?limit=10")
    except (httpx.HTTPError, ValueError):
        alerts = []
    if not alerts:
        st.caption("尚无告警。生成一条演示事件后会显示在这里。")
    for alert in alerts:
        with st.container(border=True):
            st.markdown(f"**{alert['alert_type']}** · {alert['asset_ip']} · {alert['severity']}")
            st.caption(alert["reason"])
            if alert.get("investigation_id") and st.button(
                "查看轨迹", key=f"alert_trace_{alert['alert_id']}"
            ):
                st.query_params["view"] = "trace"
                st.query_params["investigation_id"] = alert["investigation_id"]
                st.rerun()


def render_security_dashboard() -> None:
    """渲染默认工作台，连接现有 FastAPI 安全调查接口。"""
    st.markdown(STYLE, unsafe_allow_html=True)
    if not st.session_state.get("security_token"):
        _render_login()
        return
    try:
        user = _get("/security/auth/me")
    except (httpx.HTTPError, ValueError):
        st.session_state.pop("security_token", None)
        _render_login()
        return
    st.session_state["security_user"] = user
    try:
        assets = _get("/security/demo-assets")
        history = _get("/security/investigations?limit=8")
        service_info = _get("/info")
    except (httpx.HTTPError, ValueError):
        assets, history = [], []
        service_info = {}
        st.warning(f"暂时无法连接调查服务：{_base_url()}。请先启动后端，然后刷新页面。")

    _sidebar(assets, history, user)
    view = st.query_params.get("view", "security")
    if view == "users" and user["role"] == "ADMIN":
        _render_users()
        return
    if view == "trace":
        _render_trace_page(st.query_params.get("investigation_id", ""))
        return
    if view == "siem":
        _render_siem_page(assets, service_info)
        return
    st.markdown(
        '<div class="hero"><div class="eyebrow">安全事件调查 / 动态规划版</div>'
        "<h1>从一条线索，看到完整的安全调查。</h1>"
        "<p>输入主机 IP、安全问题或 CVE 编号。规划器会选择调查路径，根据发现补充任务，并用证据与知识来源支撑报告。</p></div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="info-strip">演示环境 · 数据库中的资产和安全事件均为合成样例。调查报告仅用于体验流程，请勿作为真实处置依据。</div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="section-heading">发起调查</div>', unsafe_allow_html=True)
    st.text_area(
        "调查问题",
        key="security_query",
        placeholder="例如：分析 192.168.1.10 的风险；或询问 CVE-2024-6387 如何修复。",
        height=100,
        label_visibility="collapsed",
    )
    left, middle, right = st.columns([1.6, 1.2, 3], vertical_alignment="bottom")
    with left:
        available = service_info.get("models", [])
        preferred = ["gpt-4o-mini", "gpt-5.4-mini", "deepseek-reasoner"]
        choices = [name for name in preferred if name in available]
        choices.extend(name for name in available if name not in choices)
        model = st.selectbox("分析模型", choices or ["gpt-4o-mini"])
    with middle:
        run = st.button("开始安全调查  →", type="primary", width="stretch")
    with right:
        st.caption("调查通常需要几十秒；模型不可用时仍会返回规则与证据报告。")

    if run:
        query = st.session_state.get("security_query", "").strip()
        if not query:
            st.warning("请先输入调查问题或安全知识问题。")
        else:
            _run_investigation(query, model)

    result = st.session_state.get("security_result")
    if result:
        _show_result(result)
    else:
        st.markdown('<div class="section-heading">调查会如何展开</div>', unsafe_allow_html=True)
        steps = st.columns(4, gap="medium")
        for column, number, title, detail in zip(
            steps,
            ["01", "02", "03", "04"],
            ["理解问题", "动态执行", "证据补查", "生成报告"],
            [
                "生成与问题匹配的计划",
                "只运行需要的任务",
                "结合结果追加调查步骤",
                "说明证据、知识来源与不确定性",
            ],
            strict=True,
        ):
            with column:
                _card(f"步骤 {number}", title, detail)
