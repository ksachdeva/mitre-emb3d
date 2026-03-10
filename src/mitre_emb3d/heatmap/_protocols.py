from enum import StrEnum
from typing import Annotated, Protocol

from pydantic import Field

from mitre_emb3d._models import Emb3dCategory
from mitre_emb3d.heatmap._models import HeatMapUpdateInfo, ThreatHeatMap, ThreatState

ProjectName = Annotated[
    str,
    Field(
        description="Name of the project",
        min_length=1,
        pattern=r"^\S+$",
    ),
]


class HeatMapStorageType(StrEnum):
    JSON = "json"
    # Future storage types can be added here (e.g. SQL, NoSQL, etc.)


class HeatMapStorage(Protocol):
    async def initialize(self, name: ProjectName, description: str) -> None: ...
    async def read_entries(self, name: ProjectName, category: Emb3dCategory) -> list[ThreatState]: ...
    async def read_entry(self, name: ProjectName, category: Emb3dCategory, threat_id: str) -> ThreatState: ...
    async def update_entry(
        self,
        name: ProjectName,
        category: Emb3dCategory,
        threat_id: str,
        update_info: HeatMapUpdateInfo,
    ) -> None: ...

    # Below are the methods for the entire heatmap
    async def read_heatmap(self, name: ProjectName) -> ThreatHeatMap: ...
    async def delete_heatmap(self, name: ProjectName) -> None: ...
    async def update_heatmap(self, name: ProjectName, heatmap: ThreatHeatMap) -> None: ...
