import os
from pathlib import Path
from typing import Final

from xdg_base_dirs import xdg_cache_home, xdg_config_home, xdg_data_home

_MITRE_EMB3D_DATA_HOME_ENV_VAR: Final[str] = "MITRE_EMB3D_DATA_HOME"


def _get_data_home() -> Path:
    env_mitre_emb3d_data = os.getenv(_MITRE_EMB3D_DATA_HOME_ENV_VAR, None)
    if env_mitre_emb3d_data:
        return Path(env_mitre_emb3d_data).expanduser().resolve()
    return xdg_data_home()


def _get_cache_home() -> Path:
    env_mitre_emb3d_data = os.getenv(_MITRE_EMB3D_DATA_HOME_ENV_VAR, None)
    if env_mitre_emb3d_data:
        return Path(env_mitre_emb3d_data).joinpath("cache").expanduser().resolve()
    return xdg_cache_home()


def _get_config_home() -> Path:
    env_mitre_emb3d_data = os.getenv(_MITRE_EMB3D_DATA_HOME_ENV_VAR, None)
    if env_mitre_emb3d_data:
        return Path(env_mitre_emb3d_data).joinpath("config").expanduser().resolve()
    return xdg_config_home()


def _mitre_emb3d_directory(root: Path) -> Path:
    directory = root / "mitre-emb3d"
    directory.mkdir(exist_ok=True, parents=True)
    return directory


def data_directory() -> Path:
    return _mitre_emb3d_directory(_get_data_home())


def cache_directory() -> Path:
    return _mitre_emb3d_directory(_get_cache_home())


def config_directory() -> Path:
    return _mitre_emb3d_directory(_get_config_home())
