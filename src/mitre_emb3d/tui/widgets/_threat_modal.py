from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    Label,
    Markdown,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from mitre_emb3d._graph import get_mitigation_from_id, get_threat_from_id
from mitre_emb3d._models import Threat, ThreatState

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

        threat: Threat = get_threat_from_id(self.app.graph, self._threat_state.threat_id)  # type: ignore

        with Vertical(id="threat-modal-dialog"):
            yield Static(f"Threat: {self._threat_state.threat_id}", id="threat-modal-title")

            with TabbedContent():
                with TabPane("Assessment", id="tab-assessment"):
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
                                yield Checkbox(mid.mitigation_id, mid.applied, id=f"mitigation-{mid.mitigation_id}")
                        else:
                            yield Static("No mitigations available.")

                    yield Label("Remarks")
                    yield TextArea(self._threat_state.notes, id="remarks-area")

                    with Horizontal(id="threat-modal-buttons"):
                        yield Button("Save", variant="primary", id="modal-save")
                        yield Button("Cancel", variant="default", id="modal-cancel")

                with TabPane("Threat Description", id="tab-threat-description"):
                    with VerticalScroll():
                        yield Markdown(markdown=threat.display(), id="threat-description-md")

                with TabPane("Mitigations", id="tab-mitigations"):
                    if self._threat_state.mitigations:
                        with TabbedContent():
                            for mid in self._threat_state.mitigations:
                                with TabPane(mid.mitigation_id, id=f"tab-mitigation-{mid.mitigation_id}"):
                                    with VerticalScroll():
                                        mitigation = get_mitigation_from_id(self.app.graph, mid.mitigation_id)  # type: ignore
                                        yield Markdown(
                                            markdown=mitigation.display(), id=f"mitigation-md-{mid.mitigation_id}"
                                        )
                    else:
                        yield Static("No mitigations available.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "modal-save":
            resolution_select = self.query_one("#resolution-select", Select)
            self._threat_state.resolution = resolution_select.value

            for mid in self._threat_state.mitigations:
                checkbox = self.query_one(f"#mitigation-{mid.mitigation_id}", Checkbox)
                mid.applied = checkbox.value

            remarks_area = self.query_one("#remarks-area", TextArea)
            self._threat_state.notes = remarks_area.text

            self.app.save_heatmap()  # type: ignore

        self.dismiss(None)
