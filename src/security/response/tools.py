"""响应工具仅返回模拟结果，没有网络或主机副作用。"""


def simulate_action(action: dict[str, str], investigation_id: str) -> dict[str, str]:
    kind = action["type"]
    target = action["target"]
    if kind == "create_ticket":
        return {
            "type": kind,
            "target": target,
            "status": "模拟完成",
            "ticket_id": f"INC-{investigation_id[:8].upper()}",
            "message": "演示工单已生成；未连接真实工单系统。",
        }
    if kind == "block_ip":
        return {
            "type": kind,
            "target": target,
            "status": "模拟完成",
            "message": f"已模拟封禁 {target}；未修改任何防火墙规则。",
        }
    raise ValueError("不支持的响应动作")
