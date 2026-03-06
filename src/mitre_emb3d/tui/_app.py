from pathlib import Path
from typing import Any

import networkx as nx
from textual.app import App, ComposeResult
from textual.widgets import Footer, Header

from mitre_emb3d._models import ThreatHeatMap

from .widgets import ThreatLegend


class MEDApp(App[None]):
    BINDINGS = [("ctrl+c", "quit", "Quit")]

    CSS_PATH = Path(__file__).parent / "mbed.scss"

    def __init__(self, graph: nx.DiGraph, heatmap_file: Path, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._graph = graph
        self._heatmap_file = heatmap_file
        self._heatmap = ThreatHeatMap.model_validate_json(heatmap_file.read_text())

    def compose(self) -> ComposeResult:
        yield Header()
        yield ThreatLegend()
        yield Footer()
