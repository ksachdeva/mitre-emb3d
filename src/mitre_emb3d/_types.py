from ._graph import MITREGraph
from .ai._typer_context import AITyperContext


class CmdState:
    def __init__(self) -> None:
        self._graph: MITREGraph | None = None
        self._pprint: bool = False
        self._ai: AITyperContext = AITyperContext()

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

    @property
    def ai(self) -> AITyperContext:
        return self._ai
