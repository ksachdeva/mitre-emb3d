from textual.widgets import Static

from mitre_emb3d._models import ThreatState

from ._resolution import RESOLUTION_CSS, RESOLUTION_SHORT
from ._threat_modal import ThreatModal


class ThreatEntry(Static):
    """A single, clickable cell in the heatmap."""

    def __init__(self, threat_state: ThreatState) -> None:
        label = f"{threat_state.threat_id} [{RESOLUTION_SHORT[threat_state.resolution]}]"
        super().__init__(label)
        self.threat_id = threat_state.threat_id
        self._threat_state = threat_state
        self.add_class(RESOLUTION_CSS[threat_state.resolution])

    def on_click(self) -> None:
        self.app.push_screen(ThreatModal(self._threat_state))
