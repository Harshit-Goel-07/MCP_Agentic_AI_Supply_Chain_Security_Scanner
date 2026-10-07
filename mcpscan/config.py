"""Runtime configuration for MCPScan.

Configuration is layered: defaults < ``mcpscan.toml`` (if present) < environment variables
(prefixed ``MCPSCAN_``) < explicit CLI flags. All settings are validated by pydantic.
"""

from __future__ import annotations

from enum import StrEnum
from functools import total_ordering
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


@total_ordering
class Severity(StrEnum):
    """Ordered finding severities. Use :meth:`rank` for comparisons."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank == other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __hash__(self) -> int:
        return hash(self.value)


class LLMProvider(StrEnum):
    NONE = "none"
    OLLAMA = "ollama"
    CLAUDE = "claude"
    OPENAI = "openai"


class Settings(BaseSettings):
    """Global scanner settings."""

    model_config = SettingsConfigDict(
        env_prefix="MCPSCAN_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Analysis behaviour
    enable_semantic: bool = Field(
        default=False,
        description="Enable TF-IDF/embedding semantic analysis (requires the 'semantic' extra).",
    )
    enable_dynamic: bool = Field(
        default=False,
        description="Enable Docker sandbox behavioural (ATPA) analysis.",
    )
    max_flow_hops: int = Field(default=4, ge=1, le=8)

    # LLM judge (optional, off by default for determinism/offline use)
    llm_provider: LLMProvider = LLMProvider.NONE
    llm_model: str = "qwen2.5-coder"
    llm_endpoint: str = "http://localhost:11434"
    llm_api_key: str | None = None
    llm_cache_dir: Path = Path(".mcpscan-cache")

    # Reporting
    fail_on: Severity = Severity.HIGH

    # Persistence (optional)
    neo4j_uri: str | None = None
    neo4j_user: str = "neo4j"
    neo4j_password: str | None = None

    def semantic_available(self) -> bool:
        return self.enable_semantic


def load_settings(**overrides: object) -> Settings:
    """Load settings, applying explicit overrides (typically from the CLI)."""

    return Settings(**overrides)  # type: ignore[arg-type]
