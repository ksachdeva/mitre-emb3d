from pathlib import Path

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import Emb3dCategory
from mitre_emb3d.heatmap._models import HeatMapUpdateInfo, ThreatHeatMap, ThreatState
from mitre_emb3d.heatmap._protocols import HeatMapProjectDoesNotExistError, HeatMapStorage, ProjectName
from mitre_emb3d.heatmap._utils import make_default_heatmap


def _heatmap_file(output_dir: Path, name: ProjectName) -> Path:
    name = name.lower()
    return output_dir / f"{name}-heatmap.json"


def _get_or_raise_heatmap_file(output_dir: Path, name: ProjectName) -> Path:
    heatmap_file = _heatmap_file(output_dir, name)
    if not heatmap_file.exists():
        raise HeatMapProjectDoesNotExistError(name)
    return heatmap_file


def _raise_if_threat_not_found(mitre_graph: MITREGraph, category: Emb3dCategory, threat_id: str) -> None:
    # check for this category the threat_id exists in the graph
    threats = mitre_graph.get_threats_for_category(category)
    if not any(v.id == threat_id for v in threats):
        raise ValueError(f"Threat ID '{threat_id}' not found in category '{category}'")


class JSONHeatMapStorage(HeatMapStorage):
    def __init__(self, mitre_graph: MITREGraph, heatmap_dir: Path) -> None:
        self._output_dir = heatmap_dir
        self._mitre_graph = mitre_graph

    async def initialize(self, name: ProjectName, description: str) -> None:
        heatmap = make_default_heatmap(
            self._mitre_graph,
            name=name,
            description=description,
        )

        self._output_dir.mkdir(parents=True, exist_ok=True)

        heatmap_file = _heatmap_file(self._output_dir, name)
        heatmap_file.write_text(heatmap.model_dump_json(indent=2))

    async def project_exists(self, name: ProjectName) -> bool:
        heatmap_file = _heatmap_file(self._output_dir, name)
        return heatmap_file.exists()

    async def read_heatmap(self, name: ProjectName) -> ThreatHeatMap:
        heatmap_file = _get_or_raise_heatmap_file(self._output_dir, name)
        return ThreatHeatMap.model_validate_json(heatmap_file.read_text())

    async def delete_heatmap(self, name: ProjectName) -> None:
        heatmap_file = _get_or_raise_heatmap_file(self._output_dir, name)
        heatmap_file.unlink()

    async def update_heatmap(self, name: ProjectName, heatmap: ThreatHeatMap) -> None:
        heatmap_file = _get_or_raise_heatmap_file(self._output_dir, name)
        heatmap_file.write_text(heatmap.model_dump_json(indent=2))

    async def read_entries(self, name: ProjectName, category: Emb3dCategory) -> list[ThreatState]:
        heatmap_file = _get_or_raise_heatmap_file(self._output_dir, name)

        heatmap_data = ThreatHeatMap.model_validate_json(heatmap_file.read_text())

        category_map = {
            Emb3dCategory.NETWORKING: heatmap_data.networking,
            Emb3dCategory.SYSTEM_SW: heatmap_data.system_software,
            Emb3dCategory.APP_SW: heatmap_data.application_software,
            Emb3dCategory.HARDWARE: heatmap_data.hardware,
        }

        return category_map.get(category, [])

    async def read_entry(self, name: ProjectName, category: Emb3dCategory, threat_id: str) -> ThreatState:
        _raise_if_threat_not_found(self._mitre_graph, category, threat_id)

        entries = await self.read_entries(name, category)
        for entry in entries:
            if entry.threat_id == threat_id:
                return entry

        raise ValueError(f"Threat ID {threat_id} not found in heatmap for project {name} and category {category}")

    async def update_entry(
        self,
        name: ProjectName,
        category: Emb3dCategory,
        threat_id: str,
        update_info: HeatMapUpdateInfo,
    ) -> None:
        _raise_if_threat_not_found(self._mitre_graph, category, threat_id)

        heatmap_file = _get_or_raise_heatmap_file(self._output_dir, name)
        heatmap_data = ThreatHeatMap.model_validate_json(heatmap_file.read_text())

        if update_info.resolution:
            heatmap_data.update_threat_status(category, threat_id, update_info.resolution)

        for audit_entry in update_info.audit_log:
            heatmap_data.add_audit_entry(category, threat_id, audit_entry)

        for mitigation_info in update_info.mitigation_infos:
            if mitigation_info.resolution:
                heatmap_data.update_mitigation_status(
                    category,
                    threat_id,
                    mitigation_info.mitigation_id,
                    mitigation_info.resolution,
                )

            for mit_audit_entry in mitigation_info.audit_log:
                heatmap_data.add_mitigation_audit_entry(
                    category,
                    threat_id,
                    mitigation_info.mitigation_id,
                    mit_audit_entry,
                )

        heatmap_file.write_text(heatmap_data.model_dump_json(indent=2))
