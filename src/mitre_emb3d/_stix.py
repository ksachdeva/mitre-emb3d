import logging
from pathlib import Path

import httpx
import networkx as nx

from ._graph import build_split_graph
from ._locations import cache_directory
from ._models import StixBundle

_LOGGER = logging.getLogger(__name__)


def _download_release(release: str, output_path: Path) -> None:
    """Downloads the STIX bundle for a specific release from the MITRE EMB3D website."""
    _LOGGER.info(f"Fetching documentation for release {release} ...")

    url = f"https://emb3d.mitre.org/assets/emb3d-stix-{release}.json"
    response = httpx.get(url)
    response.raise_for_status()  # Ensure we got a successful response
    output_path.write_text(response.text)


def load_stix_bunlde(release: str) -> nx.DiGraph:
    """Download stix spec and convert it into DiGraph"""
    # cache file_name
    file_name = cache_directory().joinpath(f"emb3d-stix-{release}.json")

    if not file_name.exists():
        _download_release(release, file_name)

    _LOGGER.info(f"Loading emb3d-stix-{release}.json from cache ...")
    bundle_doc = StixBundle.model_validate_json(file_name.read_text())

    return build_split_graph(bundle_doc)
