"""安全事件调查工作台的独立启动入口。"""

import os
import subprocess
import sys

import streamlit as st
from dotenv import load_dotenv
from streamlit.runtime.scriptrunner import get_script_run_ctx

from security_dashboard import render_security_dashboard


def main() -> None:
    load_dotenv()
    st.set_page_config(page_title="Security Investigation Agent", page_icon="🔎")
    render_security_dashboard()


if __name__ == "__main__" and get_script_run_ctx() is None:
    # 允许在 PyCharm 中直接运行此文件。
    load_dotenv()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            __file__,
            "--server.port",
            os.getenv("STREAMLIT_PORT", "8501"),
        ],
        check=True,
    )
else:
    main()
