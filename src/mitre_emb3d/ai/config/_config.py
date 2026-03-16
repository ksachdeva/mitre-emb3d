from pathlib import Path
from typing import ClassVar

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from ._agent import LiteLlmProviderConfig, ProperyMapperAgentConfig


class Settings(BaseSettings):
    model_config = SettingsConfigDict()

    ignore: list[str] = []

    property_mapper_agent: ProperyMapperAgentConfig

    litellm_provider: dict[str, LiteLlmProviderConfig]

    _toml_file: ClassVar[Path]

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            TomlConfigSettingsSource(settings_cls, cls._toml_file),
            env_settings,
            dotenv_settings,
            file_secret_settings,
        )
