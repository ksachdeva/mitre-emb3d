from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import Emb3dCategory, ThreatInfo

from ._models import MitigationState, ThreatHeatMap, ThreatResolution, ThreatState


def make_default_heatmap(mitre_graph: MITREGraph, name: str, description: str) -> ThreatHeatMap:
    heatmap = ThreatHeatMap(
        name=name,
        description=description,
    )

    def _make_threat_state(threat: ThreatInfo) -> ThreatState:
        mitigations = mitre_graph.get_mitigations(threat_id=threat.id)
        mitigations_states = [MitigationState(mitigation_id=mit.id, maturity=mit.maturity) for mit in mitigations]
        return ThreatState(
            threat_id=threat.id,
            resolution=ThreatResolution.NOT_INVESTIGATED,
            mitigations=mitigations_states,
        )

    get_threats_for_category = mitre_graph.get_threats_for_category

    heatmap.hardware = [_make_threat_state(v) for v in get_threats_for_category(Emb3dCategory.HARDWARE)]
    heatmap.system_software = [_make_threat_state(v) for v in get_threats_for_category(Emb3dCategory.SYSTEM_SW)]
    heatmap.application_software = [_make_threat_state(v) for v in get_threats_for_category(Emb3dCategory.APP_SW)]
    heatmap.networking = [_make_threat_state(v) for v in get_threats_for_category(Emb3dCategory.NETWORKING)]

    return heatmap
