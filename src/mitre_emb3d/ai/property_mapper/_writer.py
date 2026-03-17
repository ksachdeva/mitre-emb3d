import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import PropertyId

from ._agent import PropertyMapperOutput

_LOGGER = logging.getLogger(__name__)


def _build_document(
    result: PropertyMapperOutput,
    mitre_graph: MITREGraph,
    head_commit: str,
    ai_model: str,
) -> dict[str, Any]:
    prop = mitre_graph.get_property_from_id(result.property_id)

    evidence_entries = []
    for ev in result.evidence:
        evidence_entries.append(
            {
                "file_name": ev.file_name,
                "code_snippet": LiteralScalarString(ev.code_snippet),
            }
        )

    return {
        "ai_model": ai_model,
        "head_commit": head_commit,
        "updated_at": datetime.now(UTC),
        "property_id": result.property_id,
        "property_name": prop.name,
        "category": prop.category.value,
        "is_applicable": result.is_relevant,
        "evidence": evidence_entries,
    }


def write_property_results(
    results: dict[PropertyId, PropertyMapperOutput],
    mitre_graph: MITREGraph,
    output_dir: Path,
    head_commit: str,
    ai_model: str,
) -> None:
    properties_dir = output_dir / "properties"
    properties_dir.mkdir(parents=True, exist_ok=True)

    yaml = YAML()
    yaml.default_flow_style = False

    for pid, result in results.items():
        doc = _build_document(result, mitre_graph, head_commit, ai_model)
        out_path = properties_dir / f"{pid}.yaml"

        with out_path.open("w") as f:
            yaml.dump(doc, f)

        _LOGGER.info(f"Wrote {out_path}")
