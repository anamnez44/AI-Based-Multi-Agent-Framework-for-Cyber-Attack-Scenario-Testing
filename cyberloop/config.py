from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration read from environment variables and the .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    llm_provider: Literal["ollama", "openai", "anthropic"] = "ollama"
    llm_model: str = "qwen3.5:4b"
    llm_temperature: float = 0.0
    llm_seed: int = 42
    llm_max_retries: int = 2
    llm_num_ctx: int = 4096
    ollama_base_url: str = "http://localhost:11434"
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None

    target_url: str = "http://localhost:8080"
    max_iterations: int = 3
