from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, Select, Static, TextArea

from mitre_emb3d._models import ThreatState

from ._resolution import RESOLUTION_LABEL


class ThreatModal(ModalScreen[None]):
    """Modal dialog for editing a threat's resolution and selecting mitigations."""

    BINDINGS = [("escape", "dismiss", "Close")]

    def __init__(
        self,
        threat_state: ThreatState,
    ) -> None:
        super().__init__()
        self._threat_state = threat_state

    def compose(self) -> ComposeResult:
        resolution_options = [(label, resolution) for resolution, label in RESOLUTION_LABEL.items()]

        with Vertical(id="threat-modal-dialog"):
            yield Static(f"Threat: {self._threat_state.threat_id}", id="threat-modal-title")

            yield Label("Resolution")
            yield Select(
                resolution_options,
                value=self._threat_state.resolution,
                id="resolution-select",
            )

            yield Label("Mitigations")
            with VerticalScroll(id="mitigation-list"):
                if self._threat_state.mitigations:
                    for mid in self._threat_state.mitigations:
                        yield Checkbox(mid.mitigation_id, id=f"mitigation-{mid.mitigation_id}")
                else:
                    yield Static("No mitigations available.")

            yield Label("Remarks")
            yield TextArea(id="remarks-area")

            with Horizontal(id="threat-modal-buttons"):
                yield Button("Save", variant="primary", id="modal-save")
                yield Button("Cancel", variant="default", id="modal-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)
