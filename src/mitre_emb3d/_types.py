import networkx as nx

from ._models import StixBundle


class CmdState:
    def __init__(self) -> None:
        self._doc: StixBundle | None = None
        self._graph: nx.DiGraph | None = None

    @property
    def graph(self) -> nx.DiGraph:
        if self._graph is None:
            raise ValueError("Graph has not been built yet")
        return self._graph

    @graph.setter
    def graph(self, value: nx.DiGraph) -> None:
        self._graph = value

    @property
    def doc(self) -> StixBundle:
        if self._doc is None:
            raise ValueError("StixBundle has not been set")
        return self._doc

    @doc.setter
    def doc(self, value: StixBundle) -> None:
        self._doc = value
