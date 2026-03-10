from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Label, Static

from mitre_emb3d.heatmap import ThreatResolution

from ._resolution import RESOLUTION_CSS, THREAT_RESOLUTION_LABEL


class ThreatLegendItem(Horizontal):
    """One entry in the legend: coloured swatch + text label."""

    def __init__(self, resolution: ThreatResolution) -> None:
        super().__init__()
        self._resolution = resolution

    def compose(self) -> ComposeResult:
        swatch = Static(" ")
        swatch.add_class("threat-legend-swatch", RESOLUTION_CSS[self._resolution])
        yield swatch
        yield Label(THREAT_RESOLUTION_LABEL[self._resolution])


class ThreatLegend(Horizontal):
    """Horizontal bar showing all resolution colours and their meaning."""

    def compose(self) -> ComposeResult:
        for resolution in ThreatResolution:
            yield ThreatLegendItem(resolution)
