"""安全事件调查系统的 HTTP 入口。"""

from fastapi import FastAPI

from core import settings
from security.api import router as investigation_router
from security.api import trace_page_router
from security.auth import router as auth_router

app = FastAPI(
    title="Security Investigation Agent",
    description="基于 LangGraph 的安全事件调查与模拟 SIEM 工作台",
    version="1.0.0",
)
app.include_router(auth_router)
app.include_router(investigation_router)
app.include_router(trace_page_router)


@app.get("/health", tags=["系统"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/info", tags=["系统"])
def info() -> dict[str, object]:
    """向工作台提供可用模型；不暴露密钥或内部配置。"""
    return {
        "name": "Security Investigation Agent",
        "models": sorted(model.value for model in settings.AVAILABLE_MODELS),
        "default_model": settings.DEFAULT_MODEL.value,
    }
