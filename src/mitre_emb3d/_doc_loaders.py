import logging
from pathlib import Path

import httpx

from ._models import StixBundle

_LOGGER = logging.getLogger(__name__)


def from_json(json_path: Path) -> StixBundle:
    """Builds the graph from a JSON file containing STIX items."""
    return StixBundle.model_validate_json(json_path.read_text())


def from_release(release: str) -> StixBundle:
    _LOGGER.info(f"Fetching documentation for release {release} ...")

    url = f"https://emb3d.mitre.org/assets/emb3d-stix-{release}.json"
    response = httpx.get(url)
    response.raise_for_status()  # Ensure we got a successful response
    return StixBundle.model_validate_json(response.text)
