"""将事件收集到本地事件库，并交给确定性检测器。"""

from security.repository import (
    get_alert_for_event,
    get_siem_event,
    save_siem_alert,
    save_siem_event,
)
from security.siem.detector import detect
from security.siem.schema import SecurityAlert, SecurityEvent


def collect(event: SecurityEvent) -> tuple[SecurityEvent, SecurityAlert | None, bool]:
    """重复的事件编号只处理一次，避免重复触发调查。"""
    existing = get_siem_event(event.event_id)
    if existing:
        if existing != event.model_dump(mode="json"):
            raise ValueError("事件编号已存在且内容不同")
        stored_alert = get_alert_for_event(event.event_id)
        return event, SecurityAlert.model_validate(stored_alert) if stored_alert else None, False
    save_siem_event(event.model_dump(mode="json"))
    alert = detect(event)
    if alert:
        save_siem_alert(alert.model_dump(mode="json"))
    return event, alert, True
