"""
Network IDS Simulation - Production Configuration & Environment Validation
============================================================================
Validated using Pydantic Settings with strict types, defaults, and bounds.
Fails fast if any critical environment variable is malformed.
"""

from typing import List, Union
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import os
import logging

logger = logging.getLogger("ids.config")


class Settings(BaseSettings):
    """Production application settings with environment variable parsing."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Server Configuration
    host: str = Field(default="0.0.0.0", description="Bind host address")
    port: int = Field(default=8000, ge=1024, le=65535, description="Server port")
    debug: bool = Field(default=False, description="Debug mode")
    cors_origins: List[str] = Field(
        default=["*"],
        description="Allowed CORS origins"
    )

    # Database Configuration
    database_path: str = Field(
        default="data/ids_database.db",
        description="SQLite database path"
    )

    # Detection & ML Configuration
    ml_enabled: bool = Field(default=True, description="Enable machine learning detection")
    model_path: str = Field(default="models/ids_model.joblib", description="Path to saved ML model bundle")

    # Risk Fusion Weights
    rule_weight: float = Field(default=0.4, ge=0.0, le=1.0, description="Weight for signature rules")
    anomaly_weight: float = Field(default=0.3, ge=0.0, le=1.0, description="Weight for statistical anomaly")
    ml_weight: float = Field(default=0.3, ge=0.0, le=1.0, description="Weight for ML probability")

    # Alert & Correlation
    alert_min_risk_score: float = Field(default=20.0, ge=0.0, le=100.0, description="Minimum risk score to emit alert")
    correlation_time_window: int = Field(default=60, ge=5, le=3600, description="Sliding window (seconds) for alert grouping")
    correlation_max_group: int = Field(default=100, ge=2, le=1000, description="Maximum alerts per correlation group")

    # Security & Rate Limiting
    rate_limit_per_minute: int = Field(default=600, ge=10, description="Max requests per minute per IP")

    # Simulator Settings
    simulator_mode: str = Field(default="mixed", description="Simulation mode: normal, mixed, attack_sim")
    simulator_speed: str = Field(default="fast", description="Simulation speed: slow, fast")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.strip() == "*":
                return ["*"]
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @model_validator(mode="after")
    def validate_weights(self) -> "Settings":
        """Validate and adjust weights if ML is disabled."""
        if not self.ml_enabled:
            # Rebalance rule & anomaly weights if ML is inactive
            total = self.rule_weight + self.anomaly_weight
            if total > 0:
                self.rule_weight = round(self.rule_weight / total, 2)
                self.anomaly_weight = round(1.0 - self.rule_weight, 2)
                self.ml_weight = 0.0
        else:
            total = self.rule_weight + self.anomaly_weight + self.ml_weight
            if abs(total - 1.0) > 0.05:
                logger.warning(
                    "Weights (rule=%.2f, anomaly=%.2f, ml=%.2f) do not sum to 1.0 (sum=%.2f). Auto-normalizing.",
                    self.rule_weight, self.anomaly_weight, self.ml_weight, total
                )
                self.rule_weight = round(self.rule_weight / total, 3)
                self.anomaly_weight = round(self.anomaly_weight / total, 3)
                self.ml_weight = round(1.0 - self.rule_weight - self.anomaly_weight, 3)
        return self


# Global singleton instance
settings = Settings()
