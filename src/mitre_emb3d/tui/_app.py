from math import ceil
from pathlib import Path
from typing import Any

import networkx as nx
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Footer, Header, Static

from mitre_emb3d._models import ThreatHeatMap

from .widgets import ThreatEntry, ThreatLegend


class MEDApp(App[None]):
    BINDINGS = [("ctrl+c", "quit", "Quit")]

    CSS_PATH = Path(__file__).parent / "mbed.scss"

    def __init__(self, graph: nx.DiGraph, heatmap_file: Path, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._graph = graph
        self._heatmap_file = heatmap_file
        self._heatmap = ThreatHeatMap.model_validate_json(heatmap_file.read_text())
        self.title = self._heatmap.name
        self.sub_title = self._heatmap.description

    @property
    def graph(self) -> nx.DiGraph:
        return self._graph

    def save_heatmap(self) -> None:
        self._heatmap_file.write_text(self._heatmap.model_dump_json(indent=2))

    def compose(self) -> ComposeResult:
        yield Header()
        yield ThreatLegend()

        app_sw = self._heatmap.application_software
        mid = ceil(len(app_sw) / 2)

        with VerticalScroll(id="heatmap-scroll"):
            with Horizontal(id="heatmap-grid"):
                with Vertical(classes="heatmap-column"):
                    yield Static("Networking", classes="column-header")
                    for state in self._heatmap.networking:
                        yield ThreatEntry(state)
                with Vertical(classes="heatmap-column"):
                    yield Static("Hardware", classes="column-header")
                    for state in self._heatmap.hardware:
                        yield ThreatEntry(state)
                with Vertical(classes="heatmap-column"):
                    yield Static("System\nSoftware", classes="column-header")
                    for state in self._heatmap.system_software:
                        yield ThreatEntry(state)
                with Vertical(classes="heatmap-column-wide"):
                    yield Static("Application Software", classes="column-header")
                    with Horizontal(classes="app-sw-columns"):
                        with Vertical(classes="app-sw-sub"):
                            for state in app_sw[:mid]:
                                yield ThreatEntry(state)
                        with Vertical(classes="app-sw-sub"):
                            for state in app_sw[mid:]:
                                yield ThreatEntry(state)
        yield Footer()
