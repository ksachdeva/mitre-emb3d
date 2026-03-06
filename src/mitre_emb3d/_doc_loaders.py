import logging
from pathlib import Path

import httpx

from ._models import StixBundle

_LOGGER = logging.getLogger(__name__)


def from_json(json_path: Path) -> StixBundle:
    """Builds the graph from a JSON file containing STIX items."""
    return StixBundle.model_validate_json(json_path.read_text())


def download_release(release: str, output_path: Path) -> None:
    """Downloads the STIX bundle for a specific release from the MITRE EMB3D website."""
    _LOGGER.info(f"Fetching documentation for release {release} ...")

    url = f"https://emb3d.mitre.org/assets/emb3d-stix-{release}.json"
    response = httpx.get(url)
    response.raise_for_status()  # Ensure we got a successful response
    output_path.write_text(response.text)
