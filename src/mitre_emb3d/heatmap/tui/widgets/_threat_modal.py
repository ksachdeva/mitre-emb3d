from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Label,
    Markdown,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from mitre_emb3d._graph import get_mitigation_from_id, get_threat_from_id
from mitre_emb3d._models import Threat
from mitre_emb3d.heatmap import MitigationResolution, ThreatResolution, ThreatState


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
        resolution_options = [(res.name, res.value) for res in ThreatResolution]
        mitigation_resolution_options = [(res.name, res.value) for res in MitigationResolution]

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

                    with VerticalScroll():
                        yield Markdown(markdown=threat.display(), id="threat-description-md")

                with TabPane("Mitigations", id="tab-mitigations"):
                    if self._threat_state.mitigations:
                        with TabbedContent():
                            for mitigation_state in self._threat_state.mitigations:
                                with TabPane(
                                    mitigation_state.mitigation_id,
                                    id=f"tab-mitigation-{mitigation_state.mitigation_id}",
                                ):
                                    with VerticalScroll():
                                        yield Label("Resolution")
                                        yield Select(
                                            mitigation_resolution_options,
                                            value=mitigation_state.resolution.value,
                                            id=f"mitigation-resolution-select-{mitigation_state.mitigation_id}",
                                        )

                                        mitigation = get_mitigation_from_id(
                                            self.app.graph,  # type: ignore
                                            mitigation_state.mitigation_id,
                                        )

                                        yield Markdown(
                                            markdown=mitigation.display(),
                                            id=f"mitigation-md-{mitigation.mitigation_id}",
                                        )
                    else:
                        yield Static("No mitigations available.")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        widget_id = event.select.id or ""
        if widget_id == "resolution-select":
            self._threat_state.resolution = ThreatResolution(event.value)  # type: ignore
            self.app.save_heatmap()  # type: ignore
        elif widget_id.startswith("mitigation-resolution-select-"):
            mitigation_id = widget_id.removeprefix("mitigation-resolution-select-")
            for mitigation_state in self._threat_state.mitigations:
                if mitigation_state.mitigation_id == mitigation_id:
                    mitigation_state.resolution = MitigationResolution(event.value)  # type: ignore
                    self.app.save_heatmap()  # type: ignore
                    break
