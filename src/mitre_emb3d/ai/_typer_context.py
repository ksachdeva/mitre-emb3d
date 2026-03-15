from pathlib import Path

from .config import Settings


class AITyperContext:
    def __init__(self) -> None:
        self._repo: Path | None = None
        self._settings: Settings | None = None

    @property
    def repo(self) -> Path:
        if self._repo is None:
            raise ValueError("Repository has not been set yet")
        return self._repo

    @repo.setter
    def repo(self, value: Path) -> None:
        self._repo = value

    @property
    def settings(self) -> Settings:
        if self._settings is None:
            raise ValueError("Settings have not been set yet")
        return self._settings

    @settings.setter
    def settings(self, value: Settings) -> None:
        self._settings = value
