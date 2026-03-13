import asyncio
from math import ceil
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Footer, Header, Static

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d.heatmap._protocols import HeatMapStorage, ProjectName

from .widgets import ThreatEntry, ThreatLegend


class MEDApp(App[None]):
    BINDINGS = [("ctrl+c", "quit", "Quit")]

    CSS_PATH = Path(__file__).parent / "mbed.scss"

    def __init__(
        self,
        mitre_graph: MITREGraph,
        project_name: ProjectName,
        heatmap_storage: HeatMapStorage,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._mitre_graph = mitre_graph
        self._heatmap_storage = heatmap_storage
        self._project_name = project_name
        self._heatmap = asyncio.run(heatmap_storage.read_heatmap(project_name))

    @property
    def graph(self) -> MITREGraph:
        return self._mitre_graph

    async def save_heatmap(self) -> None:
        await self._heatmap_storage.update_heatmap(self._project_name, self._heatmap)

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
