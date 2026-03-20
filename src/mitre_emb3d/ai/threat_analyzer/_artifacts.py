import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import PropertyId, ThreatId

from ._models import ThreatAnalyzerOutput

_LOGGER = logging.getLogger(__name__)


class MitigationEntry(TypedDict):
    mitigation_id: str
    file_name: str
    is_applied: bool
    explanation: str


class PropertyThreatEntry(TypedDict):
    property_id: str
    property_name: str
    mitigation_info: list[MitigationEntry]


class ThreatArtifactDocument(TypedDict):
    ai_model: str
    head_commit: str
    updated_at: datetime
    threat_id: str
    threat_name: str
    properties: dict[str, PropertyThreatEntry]


def _build_property_entry(
    result: ThreatAnalyzerOutput,
    mitre_graph: MITREGraph,
) -> PropertyThreatEntry:
    prop = mitre_graph.get_property_from_id(result.property_id)

    mitigation_entries = []
    for m in result.mitigation_info:
        mitigation_entries.append(
            MitigationEntry(
                mitigation_id=m.mitigation_id,
                file_name=m.file_name,
                is_applied=m.is_applied,
                explanation=LiteralScalarString(m.explanation),
            )
        )

    return PropertyThreatEntry(
        property_id=result.property_id,
        property_name=prop.name,
        mitigation_info=mitigation_entries,
    )


def _build_document(
    threat_id: ThreatId,
    property_results: dict[PropertyId, ThreatAnalyzerOutput],
    mitre_graph: MITREGraph,
    head_commit: str,
    ai_model: str,
) -> ThreatArtifactDocument:
    threat = mitre_graph.get_threat_from_id(threat_id)

    properties: dict[str, PropertyThreatEntry] = {}
    for pid, result in property_results.items():
        properties[pid] = _build_property_entry(result, mitre_graph)

    return ThreatArtifactDocument(
        ai_model=ai_model,
        head_commit=head_commit,
        updated_at=datetime.now(UTC),
        threat_id=threat_id,
        threat_name=threat.name,
        properties=properties,
    )


def write_threat_documents(
    accumulated: dict[ThreatId, dict[PropertyId, ThreatAnalyzerOutput]],
    mitre_graph: MITREGraph,
    output_dir: Path,
    head_commit: str,
    ai_model: str,
) -> None:
    threats_dir = output_dir / "threats"
    threats_dir.mkdir(parents=True, exist_ok=True)

    yaml = YAML()
    yaml.default_flow_style = False

    for threat_id, property_results in accumulated.items():
        doc = _build_document(threat_id, property_results, mitre_graph, head_commit, ai_model)
        out_path = threats_dir / f"{threat_id}.yaml"

        with out_path.open("w") as f:
            yaml.dump(doc, f)

        _LOGGER.info(f"Wrote {out_path}")
