from enum import StrEnum
from json import loads
from typing import Any

from dotenv import find_dotenv
from pydantic import (
    Field,
    SecretStr,
    computed_field,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

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
    Provider,
    VertexAIModelName,
)


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    def to_logging_level(self) -> int:
        """转换为 Python logging 级别常量。"""
        import logging

        mapping = {
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ERROR: logging.ERROR,
            LogLevel.CRITICAL: logging.CRITICAL,
        }
        return mapping[self]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=find_dotenv(),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        validate_default=False,
    )
    MODE: str | None = None

    HOST: str = "0.0.0.0"
    PORT: int = 8080
    GRACEFUL_SHUTDOWN_TIMEOUT: int = 30
    LOG_LEVEL: LogLevel = LogLevel.WARNING

    SECURITY_JWT_SECRET: SecretStr | None = None

    OPENAI_API_KEY: SecretStr | None = None
    DEEPSEEK_API_KEY: SecretStr | None = None
    DEEPSEEK_BASE_URL: str = "https://api.deepseek.com"
    DEEPSEEK_TIMEOUT: float = 180
    DEEPSEEK_MAX_RETRIES: int = 3
    DEEPSEEK_RETRY_SLEEP: float = 2.0
    AIGCBEST_API_KEY: SecretStr | None = None
    AIGCBEST_BASE_URL: str = "https://api2.aigcbest.top"
    AIGCBEST_API_PATH: str = "/v1/chat/completions"
    AIGCBEST_MAX_RETRIES: int = 3
    AIGCBEST_GPT_4O_MINI_TIMEOUT: float = 120
    AIGCBEST_GPT_54_MINI_TIMEOUT: float = 180
    AIGCBEST_RETRY_SLEEP: float = 2.0
    AIGCBEST_EMBEDDING_MODEL: str = "text-embedding-3-small"
    PRIVATE_GATEWAY_API_KEY: SecretStr | None = None
    PRIVATE_GATEWAY_API_KEY_FROM: str | None = None
    PRIVATE_GATEWAY_BASE_URL: str | None = None
    PRIVATE_GATEWAY_API_PATH: str = "/v1/chat/completions"
    PRIVATE_GATEWAY_TIMEOUT: float = 180
    PRIVATE_GATEWAY_MAX_RETRIES: int = 3
    PRIVATE_GATEWAY_RETRY_SLEEP: float = 2.0
    ANTHROPIC_API_KEY: SecretStr | None = None
    GOOGLE_API_KEY: SecretStr | None = None
    GOOGLE_APPLICATION_CREDENTIALS: SecretStr | None = None
    GROQ_API_KEY: SecretStr | None = None
    USE_AWS_BEDROCK: bool = False
    OLLAMA_MODEL: str | None = None
    OLLAMA_BASE_URL: str | None = None
    USE_FAKE_MODEL: bool = False
    OPENROUTER_API_KEY: SecretStr | None = None

    # 如果 DEFAULT_MODEL 为 None，则会在 model_post_init 中设置
    DEFAULT_MODEL: AllModelEnum | None = None  # type: ignore[assignment]
    AVAILABLE_MODELS: set[AllModelEnum] = set()  # type: ignore[assignment]

    # 设置兼容 OpenAI 的 API，主要用于概念验证
    COMPATIBLE_MODEL: str | None = None
    COMPATIBLE_API_KEY: SecretStr | None = None
    COMPATIBLE_BASE_URL: str | None = None

    # Azure OpenAI 设置
    AZURE_OPENAI_API_KEY: SecretStr | None = None
    AZURE_OPENAI_ENDPOINT: str | None = None
    AZURE_OPENAI_API_VERSION: str = "2024-02-15-preview"
    AZURE_OPENAI_DEPLOYMENT_MAP: dict[str, str] = Field(
        default_factory=dict, description="模型名称与 Azure 部署 ID 的映射"
    )

    def model_post_init(self, __context: Any) -> None:
        api_keys = {
            Provider.OPENAI: self.OPENAI_API_KEY,
            Provider.OPENAI_COMPATIBLE: self.COMPATIBLE_BASE_URL and self.COMPATIBLE_MODEL,
            Provider.DEEPSEEK: self.DEEPSEEK_API_KEY,
            Provider.AIGCBEST: self.AIGCBEST_API_KEY,
            Provider.PRIVATE_GATEWAY: self.PRIVATE_GATEWAY_API_KEY,
            Provider.ANTHROPIC: self.ANTHROPIC_API_KEY,
            Provider.GOOGLE: self.GOOGLE_API_KEY,
            Provider.VERTEXAI: self.GOOGLE_APPLICATION_CREDENTIALS,
            Provider.GROQ: self.GROQ_API_KEY,
            Provider.AWS: self.USE_AWS_BEDROCK,
            Provider.OLLAMA: self.OLLAMA_MODEL,
            Provider.FAKE: self.USE_FAKE_MODEL,
            Provider.AZURE_OPENAI: self.AZURE_OPENAI_API_KEY,
            Provider.OPENROUTER: self.OPENROUTER_API_KEY,
        }
        active_keys = [k for k, v in api_keys.items() if v]
        if not active_keys:
            raise ValueError("至少需要提供一个大模型 API 密钥。")

        # 即使存在真实提供方密钥，USE_FAKE_MODEL 也必须优先生效并覆盖默认值。
        if self.USE_FAKE_MODEL and self.DEFAULT_MODEL is None:
            self.DEFAULT_MODEL = FakeModelName.FAKE

        for provider in active_keys:
            match provider:
                case Provider.OPENAI:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = OpenAIModelName.GPT_5_NANO
                    self.AVAILABLE_MODELS.update(set(OpenAIModelName))
                case Provider.OPENAI_COMPATIBLE:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = OpenAICompatibleName.OPENAI_COMPATIBLE
                    self.AVAILABLE_MODELS.update(set(OpenAICompatibleName))
                case Provider.DEEPSEEK:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = DeepseekModelName.DEEPSEEK_V4_FLASH
                    self.AVAILABLE_MODELS.update(set(DeepseekModelName))
                case Provider.AIGCBEST:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = AigcBestModelName.GPT_4O_MINI
                    self.AVAILABLE_MODELS.update(set(AigcBestModelName))
                case Provider.PRIVATE_GATEWAY:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = PrivateGatewayModelName.GPT_54
                    self.AVAILABLE_MODELS.update(set(PrivateGatewayModelName))
                case Provider.ANTHROPIC:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = AnthropicModelName.HAIKU_45
                    self.AVAILABLE_MODELS.update(set(AnthropicModelName))
                case Provider.GOOGLE:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = GoogleModelName.GEMINI_38_FLASH
                    self.AVAILABLE_MODELS.update(set(GoogleModelName))
                case Provider.VERTEXAI:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = VertexAIModelName.GEMINI_38_FLASH
                    self.AVAILABLE_MODELS.update(set(VertexAIModelName))
                case Provider.GROQ:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = GroqModelName.GPT_OSS_20B
                    self.AVAILABLE_MODELS.update(set(GroqModelName))
                case Provider.AWS:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = AWSModelName.BEDROCK_HAIKU
                    self.AVAILABLE_MODELS.update(set(AWSModelName))
                case Provider.OLLAMA:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = OllamaModelName.OLLAMA_GENERIC
                    self.AVAILABLE_MODELS.update(set(OllamaModelName))
                case Provider.OPENROUTER:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = OpenRouterModelName.GEMINI_38_FLASH
                    self.AVAILABLE_MODELS.update(set(OpenRouterModelName))
                case Provider.FAKE:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = FakeModelName.FAKE
                    self.AVAILABLE_MODELS.update(set(FakeModelName))
                case Provider.AZURE_OPENAI:
                    if self.DEFAULT_MODEL is None:
                        self.DEFAULT_MODEL = AzureOpenAIModelName.AZURE_GPT_5_MINI
                    self.AVAILABLE_MODELS.update(set(AzureOpenAIModelName))
                    # 如果 Azure 提供方可用，则验证 Azure OpenAI 设置
                    if not self.AZURE_OPENAI_API_KEY:
                        raise ValueError("必须设置 AZURE_OPENAI_API_KEY")
                    if not self.AZURE_OPENAI_ENDPOINT:
                        raise ValueError("必须设置 AZURE_OPENAI_ENDPOINT")
                    if not self.AZURE_OPENAI_DEPLOYMENT_MAP:
                        raise ValueError("必须设置 AZURE_OPENAI_DEPLOYMENT_MAP")

                    # 如果部署映射是字符串，则进行解析
                    if isinstance(self.AZURE_OPENAI_DEPLOYMENT_MAP, str):
                        try:
                            self.AZURE_OPENAI_DEPLOYMENT_MAP = loads(
                                self.AZURE_OPENAI_DEPLOYMENT_MAP
                            )
                        except Exception as e:
                            raise ValueError(f"AZURE_OPENAI_DEPLOYMENT_MAP 的 JSON 无效：{e}")

                    # 验证所需的部署是否存在
                    required_models = {"gpt-5", "gpt-5-mini"}
                    missing_models = required_models - set(self.AZURE_OPENAI_DEPLOYMENT_MAP.keys())
                    if missing_models:
                        raise ValueError(f"缺少必需的 Azure 部署：{missing_models}")
                case _:
                    raise ValueError(f"未知的服务商：{provider}")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def BASE_URL(self) -> str:
        return f"http://{self.HOST}:{self.PORT}"

    def is_dev(self) -> bool:
        return self.MODE == "dev"


settings = Settings()
