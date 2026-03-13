from ._graph import MITREGraph
from .heatmap import HeatMapStorageType


class CmdState:
    def __init__(self) -> None:
        self._graph: MITREGraph | None = None
        self._pprint: bool = False
        self._storage_type: HeatMapStorageType = HeatMapStorageType.JSON

    @property
    def heatmap_storage_type(self) -> HeatMapStorageType:
        return self._storage_type

    @heatmap_storage_type.setter
    def heatmap_storage_type(self, value: HeatMapStorageType) -> None:
        self._storage_type = value

    @property
    def pprint(self) -> bool:
        return self._pprint

    @pprint.setter
    def pprint(self, value: bool) -> None:
        self._pprint = value

    @property
    def graph(self) -> MITREGraph:
        if self._graph is None:
            raise ValueError("Graph has not been built yet")
        return self._graph

    @graph.setter
    def graph(self, value: MITREGraph) -> None:
        self._graph = value
