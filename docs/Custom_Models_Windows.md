# 在 Windows 上运行自定义模型网关

将 `.env.example` 复制到 `.env` 并在那里添加你的 API 密钥。`.env` 会被 Git 忽略。只有在配置了相应密钥时，应用中才会显示自定义模型选项。

受支持的模型 ID 是 `gpt-4o-mini`、`gpt-5.4-mini`、`deepseek-reasoner` 和 `private-gateway-gpt-5.4`。私有网关还需要 `PRIVATE_GATEWAY_BASE_URL` 以及一个实际的 `PRIVATE_GATEWAY_API_KEY`；`PRIVATE_GATEWAY_API_KEY_FROM` 会记录外部密钥别名，但不会解析该别名。

在仓库根目录中的 PowerShell 里：

如果使用 PyCharm，先将项目解释器设置为 `.venv\Scripts\python.exe`，并将两个运行配置的工作目录设置为仓库根目录。然后先点击 `src/run_service.py` 左侧的绿色运行按钮启动后端，再点击 `src/streamlit_app.py` 左侧的绿色运行按钮启动前端。第二个文件现在会自动用 Streamlit 启动自身，因此可以直接使用普通的 Python 运行按钮。两个进程要分别保持运行；不要重复启动相同端口。

也可以在两个 PowerShell 窗口中分别运行：

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe src\run_service.py
```

在另一个 PowerShell 窗口中：

```powershell
.\.venv\Scripts\python.exe -m streamlit run src\streamlit_app.py --server.port 18501 --server.address 127.0.0.1
```

打开 `http://127.0.0.1:18501`，登录后在调查页面的“分析模型”下拉框选择已配置的模型。FastAPI 服务会使用 `.env` 中的 `PORT`；前后端不在同一台机器时，将 `AGENT_URL` 设置为后端地址。

`AIGCBEST_API_KEY`、基础 URL 和嵌入模型也会配置安全知识库的向量检索。知识文档放在 `knowledge/`；首次检索时自动建立 Chroma 索引，向量服务不可用时回退到本地关键词检索。可设置 `SECURITY_RAG_MODE=lexical` 只使用本地检索。

`max_retries` 会传递给模型 SDK。已配置的 `retry_sleep` 值会保留以供参考；SDK 会自行控制重试延迟。
