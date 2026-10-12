from functools import cache

from langchain_anthropic import ChatAnthropic
from langchain_aws import ChatBedrock
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_vertexai import ChatVertexAI
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama
from langchain_openai import AzureChatOpenAI, ChatOpenAI

from core.settings import settings
from schema.models import (
    AigcBestModelName,
    AllModelEnum,
    AnthropicModelName,
    AWSModelName,
    AzureOpenAIModelName,
    DeepseekModelName,
    FakeModelName,
    GoogleModelName,
    GroqModelName,
    OllamaModelName,
    OpenAICompatibleName,
    OpenAIModelName,
    OpenRouterModelName,
    PrivateGatewayModelName,
    VertexAIModelName,
)

_MODEL_TABLE = (
    {m: m.value for m in OpenAIModelName}
    | {m: m.value for m in OpenAICompatibleName}
    | {m: m.value for m in AzureOpenAIModelName}
    | {m: m.value for m in DeepseekModelName}
    | {m: m.value for m in AigcBestModelName}
    | {m: "openai/gpt-5.4" for m in PrivateGatewayModelName}
    | {m: m.value for m in AnthropicModelName}
    | {m: m.value for m in GoogleModelName}
    | {m: m.value for m in VertexAIModelName}
    | {m: m.value for m in GroqModelName}
    | {m: m.value for m in AWSModelName}
    | {m: m.value for m in OllamaModelName}
    | {m: m.value for m in OpenRouterModelName}
    | {m: m.value for m in FakeModelName}
)


class FakeToolModel(FakeListChatModel):
    def __init__(self, responses: list[str]):
        super().__init__(responses=responses)

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self


type ModelT = (
    AzureChatOpenAI
    | ChatOpenAI
    | ChatAnthropic
    | ChatGoogleGenerativeAI
    | ChatVertexAI
    | ChatGroq
    | ChatBedrock
    | ChatOllama
    | FakeToolModel
)


def _chat_base_url(base_url: str, api_path: str) -> str:
    suffix = "/chat/completions"
    if not api_path.endswith(suffix):
        raise ValueError("聊天 API 路径必须以 /chat/completions 结尾")
    return f"{base_url.rstrip('/')}/{api_path.removesuffix(suffix).strip('/')}"


@cache
def get_model(model_name: AllModelEnum, /) -> ModelT:
    # 注意：当 `streaming=True` 时，模型会在生成 token 的同时发送它们
    # 如果调用 `/stream` 端点时使用 `stream_tokens=True`（默认值）
    api_model_name = _MODEL_TABLE.get(model_name)
    if not api_model_name:
        raise ValueError(f"不支持的模型：{model_name}")

    if model_name in OpenAIModelName:
        return ChatOpenAI(model=api_model_name, streaming=True)
    if model_name in OpenAICompatibleName:
        if not settings.COMPATIBLE_BASE_URL or not settings.COMPATIBLE_MODEL:
            raise ValueError("必须配置 OpenAICompatible 的基础地址和端点")

        return ChatOpenAI(
            model=settings.COMPATIBLE_MODEL,
            temperature=0.5,
            streaming=True,
            openai_api_base=settings.COMPATIBLE_BASE_URL,
            openai_api_key=settings.COMPATIBLE_API_KEY,
        )
    if model_name in AzureOpenAIModelName:
        if not settings.AZURE_OPENAI_API_KEY or not settings.AZURE_OPENAI_ENDPOINT:
            raise ValueError("必须配置 Azure OpenAI API 密钥和端点")

        # GPT-5 的生成基于推理，并会拒绝 temperature（400）；请省略它。
        return AzureChatOpenAI(
            azure_endpoint=settings.AZURE_OPENAI_ENDPOINT,
            deployment_name=api_model_name,
            api_version=settings.AZURE_OPENAI_API_VERSION,
            streaming=True,
            timeout=60,
            max_retries=3,
        )
    if model_name in DeepseekModelName:
        return ChatOpenAI(
            model=api_model_name,
            streaming=True,
            openai_api_base=settings.DEEPSEEK_BASE_URL,
            openai_api_key=settings.DEEPSEEK_API_KEY,
            timeout=settings.DEEPSEEK_TIMEOUT,
            max_retries=settings.DEEPSEEK_MAX_RETRIES,
        )
    if model_name in AigcBestModelName:
        if not settings.AIGCBEST_API_KEY:
            raise ValueError("必须配置 AIGCBEST API 密钥")
        return ChatOpenAI(
            model=api_model_name,
            streaming=True,
            base_url=_chat_base_url(settings.AIGCBEST_BASE_URL, settings.AIGCBEST_API_PATH),
            api_key=settings.AIGCBEST_API_KEY,
            timeout=(
                settings.AIGCBEST_GPT_4O_MINI_TIMEOUT
                if model_name == AigcBestModelName.GPT_4O_MINI
                else settings.AIGCBEST_GPT_54_MINI_TIMEOUT
            ),
            max_retries=settings.AIGCBEST_MAX_RETRIES,
        )
    if model_name in PrivateGatewayModelName:
        if not settings.PRIVATE_GATEWAY_API_KEY or not settings.PRIVATE_GATEWAY_BASE_URL:
            raise ValueError("必须配置私有网关 API 密钥和基础地址")
        return ChatOpenAI(
            model=api_model_name,
            streaming=True,
            base_url=_chat_base_url(
                settings.PRIVATE_GATEWAY_BASE_URL, settings.PRIVATE_GATEWAY_API_PATH
            ),
            api_key=settings.PRIVATE_GATEWAY_API_KEY,
            timeout=settings.PRIVATE_GATEWAY_TIMEOUT,
            max_retries=settings.PRIVATE_GATEWAY_MAX_RETRIES,
        )
    if model_name in AnthropicModelName:
        if model_name == AnthropicModelName.SONNET_5:
            # Claude Sonnet 5 会拒绝非默认采样参数（temperature，
            # top_p、top_k），并返回 400 错误——自适应思考默认已开启
            # 而是如此。参见 https://docs.anthropic.com/en/docs/about-claude/models
            return ChatAnthropic(model_name=api_model_name, streaming=True)
        return ChatAnthropic(model_name=api_model_name, temperature=0.5, streaming=True)
    if model_name in GoogleModelName:
        return ChatGoogleGenerativeAI(model=api_model_name, temperature=0.5, streaming=True)
    if model_name in VertexAIModelName:
        return ChatVertexAI(model=api_model_name, temperature=0.5, streaming=True)
    if model_name in GroqModelName:
        if model_name == GroqModelName.GPT_OSS_SAFEGUARD_20B:
            return ChatGroq(model=api_model_name, temperature=0.0)  # type: ignore[call-arg]
        return ChatGroq(model=api_model_name, temperature=0.5)  # type: ignore[call-arg]
    if model_name in AWSModelName:
        if model_name == AWSModelName.BEDROCK_SONNET:
            # Sonnet 5 会拒绝非默认采样参数（400）；请省略 temperature。
            return ChatBedrock(model=api_model_name)
        return ChatBedrock(model=api_model_name, temperature=0.5)
    if model_name in OllamaModelName:
        if not settings.OLLAMA_MODEL:
            raise ValueError("必须配置 Ollama 模型")
        if settings.OLLAMA_BASE_URL:
            chat_ollama = ChatOllama(
                model=settings.OLLAMA_MODEL, temperature=0.5, base_url=settings.OLLAMA_BASE_URL
            )
        else:
            chat_ollama = ChatOllama(model=settings.OLLAMA_MODEL, temperature=0.5)
        return chat_ollama
    if model_name in OpenRouterModelName:
        # 如果没有显式指定 key，openai SDK 会回退到 OPENAI_API_KEY，
        # 这会把该 key 发送到 openrouter.ai。
        if not settings.OPENROUTER_API_KEY:
            raise ValueError("必须配置 OpenRouter API 密钥")

        return ChatOpenAI(
            model=api_model_name,
            temperature=0.5,
            streaming=True,
            base_url="https://openrouter.ai/api/v1/",
            api_key=settings.OPENROUTER_API_KEY,
        )
    if model_name in FakeModelName:
        return FakeToolModel(responses=["This is a test response from the fake model."])

    raise ValueError(f"不支持的模型：{model_name}")
