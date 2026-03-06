from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Label, Static

from mitre_emb3d._models import ThreatResolution

# Maps each resolution to a CSS class name and a display colour
_RESOLUTION_CSS: dict[ThreatResolution, str] = {
    ThreatResolution.NOT_INVESTIGATED: "not-investigated",
    ThreatResolution.NA: "na",
    ThreatResolution.MITIGATED: "mitigated",
    ThreatResolution.VULNERABLE: "vulnerable",
    ThreatResolution.CONDITIONALLY_MITIGATED: "conditionally-mitigated",
}

_RESOLUTION_LABEL: dict[ThreatResolution, str] = {
    ThreatResolution.NOT_INVESTIGATED: "Not Investigated",
    ThreatResolution.NA: "N/A",
    ThreatResolution.MITIGATED: "Mitigated",
    ThreatResolution.VULNERABLE: "Vulnerable",
    ThreatResolution.CONDITIONALLY_MITIGATED: "Cond. Mitigated",
}


class ThreatLegendItem(Horizontal):
    """One entry in the legend: coloured swatch + text label."""

    def __init__(self, resolution: ThreatResolution) -> None:
        super().__init__()
        self._resolution = resolution

    def compose(self) -> ComposeResult:
        swatch = Static(" ")
        swatch.add_class("threat-legend-swatch", _RESOLUTION_CSS[self._resolution])
        yield swatch
        yield Label(_RESOLUTION_LABEL[self._resolution])


class ThreatLegend(Horizontal):
    """Horizontal bar showing all resolution colours and their meaning."""

    def compose(self) -> ComposeResult:
        for resolution in ThreatResolution:
            yield ThreatLegendItem(resolution)
