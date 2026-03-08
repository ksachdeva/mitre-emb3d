import networkx as nx


class CmdState:
    def __init__(self) -> None:
        self._graph: nx.DiGraph | None = None
        self._pprint: bool = False

    @property
    def pprint(self) -> bool:
        return self._pprint

    @pprint.setter
    def pprint(self, value: bool) -> None:
        self._pprint = value

    @property
    def graph(self) -> nx.DiGraph:
        if self._graph is None:
            raise ValueError("Graph has not been built yet")
        return self._graph

    @graph.setter
    def graph(self, value: nx.DiGraph) -> None:
        self._graph = value
