"""安全工作台首次访问显示账号登录入口。"""

from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_security_dashboard_starts_at_login():
    path = Path(__file__).resolve().parents[2] / "src" / "streamlit_app.py"
    app = AppTest.from_file(str(path), default_timeout=15).run()
    assert not app.exception
    assert {item.label for item in app.text_input} >= {"用户名", "密码"}
