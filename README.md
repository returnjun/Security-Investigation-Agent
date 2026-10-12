# Security Investigation Agent

基于 **LangGraph、FastAPI、Streamlit** 的安全事件调查系统。系统支持人工问题和模拟 SIEM 告警两种入口，由 Planner 选择调查任务，汇总资产、日志、漏洞、IP 信誉和安全知识证据，再通过确定性规则评分、映射 MITRE ATT&CK，并生成可追溯的中文报告。

> 当前资产、日志、漏洞、信誉和 SIEM 事件均为本地合成数据。系统的响应动作只模拟工单创建和 IP 封禁，不连接真实安全设备；调查结论不能直接用于生产处置。

## 功能

- **动态调查**：结构化 Planner 选择资产、近 7 天历史、日志、漏洞、来源信誉和 RAG 检索任务；证据汇总后可追加补查。模型不可用时使用规则回退。
- **事件驱动**：模拟 SIEM 采集 SSH 失败登录、端口扫描、提权等事件，阈值检测命中后自动进入同一调查流程。
- **知识与证据**：安全知识库包含 CVE、应急指南和 MITRE ATT&CK；支持 Chroma 向量检索、关键词重排与本地回退，报告引用知识来源和证据编号。
- **可解释风险**：风险等级由规则计算，综合日志、漏洞、来源信誉、资产重要性和历史趋势；证据不足时给出“待确认”。
- **运营闭环**：保存调查、反馈、告警和节点轨迹；分析员、主管、管理员通过 JWT 分权。响应建议经 LangGraph `interrupt()` 暂停，主管批准后才模拟执行。
- **可视化工作台**：中文 Streamlit 界面展示调查进度、证据、报告、审批和执行轨迹。

## 运行

需要 Python 3.12～3.14。以下命令在项目根目录执行。已有虚拟环境时可以直接使用；首次安装可运行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
Copy-Item .env.example .env
```

在 `.env` 中至少配置一种模型的 API 密钥，例如 `AIGCBEST_API_KEY` 或 `DEEPSEEK_API_KEY`。只想验证本地流程时，可设置 `USE_FAKE_MODEL=true`。按需设置 `PORT=18080` 和 `STREAMLIT_PORT=18501`；默认分别为 8080 和 8501。

创建管理员账号，密码通过终端隐藏输入：

```powershell
.\.venv\Scripts\python.exe scripts\create_security_admin.py
```

分别在两个终端启动：

```powershell
.\.venv\Scripts\python.exe src\run_service.py
```

```powershell
.\.venv\Scripts\python.exe -m streamlit run src\streamlit_app.py --server.port 18501
```

然后访问 `http://127.0.0.1:18501`；API 文档在后端的 `/docs`，健康检查在 `/health`。若采用其他端口，以实际配置为准。**不要将 `.env`、`privatecredentials/`、数据库或个人简历提交到 GitHub**；仓库的 `.gitignore` 已排除这些本地文件。

也可在完成 `.env` 配置与管理员创建后运行 `docker compose up --build`。容器模式默认将后端映射到 18080、工作台映射到 18501，数据库和审批检查点保存在宿主机的 `data/` 与 `.runtime-tools/`。

## 项目结构

| 位置 | 作用 |
| --- | --- |
| `src/security/workflow.py`、`planner.py` | LangGraph 调查图、动态规划与任务执行 |
| `src/security/siem/` | 合成事件采集、检测与告警 |
| `src/security/rag/`、`knowledge/` | 安全知识加载、检索与来源引用 |
| `src/security/risk.py`、`mitre.py` | 规则评分和攻击技术映射 |
| `src/security/response/`、`auth.py` | 人工审批、模拟响应与角色权限 |
| `src/security/repository.py` | SQLite 资产、事件、调查、轨迹与账号存储 |
| `src/security/api.py`、`src/service/service.py` | 安全业务 API 与服务入口 |
| `src/security_dashboard.py`、`src/streamlit_app.py` | 前端工作台与启动入口 |
| `tests/security/` | 安全调查、权限、审批和界面测试 |

本地数据库默认位于 `data/security_investigation.db`。旧版本的 `data/security_demo.db` 若存在会继续使用，以保留已有调查和账号；也可用 `SECURITY_DB_PATH` 指定路径。响应审批检查点和 JWT 本地密钥位于被 Git 忽略的 `.runtime-tools/`。

## 验证

```powershell
.\.venv\Scripts\python.exe -m pytest tests/security -q
```

更多接口和设计说明见 [V4 设计文档](docs/Security_Investigation_V4.md)。

## 来源与许可

本项目的早期服务框架基于 Joshua Carroll 的 [Agent Service Toolkit](https://github.com/JoshuaC215/agent-service-toolkit) 扩展；当前安全调查流程、模拟 SIEM、风险规则、审批闭环与工作台为本项目的场景实现。保留原项目的 [MIT 许可证](LICENSE)及版权声明。
