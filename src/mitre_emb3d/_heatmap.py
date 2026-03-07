import sys
from pathlib import Path
from typing import Annotated, List, Optional, cast

import typer
from pydantic import TypeAdapter
from typer import Typer

from mitre_emb3d._graph import get_threats_by_category, make_default_heatmap
from mitre_emb3d._models import Emb3dCategory, ThreatHeatMap, ThreatResolution, ThreatState
from mitre_emb3d._models import StixBundle as ST
from mitre_emb3d._types import CmdState

heatmap_app = Typer(name="heatmap", help="Heatmap related commands")


@heatmap_app.command(name="init")
def init_heatmap(
    ctx: typer.Context,
    name: str,
    description: str,
    output_dir: Annotated[Path, typer.Option(help="Path to the directory that would contain the heatmap")],
) -> None:
    """Initialize a heatmap JSON file with all threats set to NOT_INVESTIGATED."""
    state = cast(CmdState, ctx.obj)
    G = state.graph

    heatmap = make_default_heatmap(
        G,
        name=name,
        description=description,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    heatmap_file = output_dir / "mitr-emb3d-heatmap.json"
    heatmap_file.write_text(heatmap.model_dump_json(indent=2))


@heatmap_app.command(name="read")
def read_heatmap(
    ctx: typer.Context,
    category: Annotated[Emb3dCategory, typer.Argument(help="Category to list threat states for")],
    heatmap_file: Annotated[
        Path,
        typer.Option(
            help="Path to the heatmap JSON file",
            file_okay=True,
            dir_okay=False,
            exists=True,
        ),
    ],
) -> None:
    """List the threat states for the given category."""

    heatmap_data = ThreatHeatMap.model_validate_json(heatmap_file.read_text())

    category_map = {
        Emb3dCategory.NETWORKING: heatmap_data.networking,
        Emb3dCategory.SYSTEM_SW: heatmap_data.system_software,
        Emb3dCategory.APP_SW: heatmap_data.application_software,
        Emb3dCategory.HARDWARE: heatmap_data.hardware,
    }

    threats = category_map.get(category, [])

    adapter = TypeAdapter(List[ThreatState])

    sys.stdout.write(adapter.dump_json(threats, indent=0).decode("utf-8"))


@heatmap_app.command(name="update")
def update_heatmap(
    ctx: typer.Context,
    category: Annotated[Emb3dCategory, typer.Argument(help="Category to update the threat state for")],
    threat_id: Annotated[
        str,
        typer.Argument(help="Threat ID to update (e.g. TID-123)"),
    ],
    threat_resolution: Annotated[ThreatResolution, typer.Argument()],
    heatmap_file: Annotated[
        Path,
        typer.Option(
            help="Path to the heatmap JSON file",
            file_okay=True,
            dir_okay=False,
            exists=True,
        ),
    ],
    applied_mitigation: Annotated[
        Optional[List[str]],
        typer.Option(
            "--am",
            help="List of applied mitigation IDs (e.g. MID-001)",
        ),
    ] = None,
    unapplied_mitigation: Annotated[
        Optional[List[str]], typer.Option("--um", help="List of unapplied mitigation IDs (e.g. MID-002)")
    ] = None,
    notes: Annotated[Optional[str], typer.Option(help="Additional notes about the threat state")] = None,
) -> None:
    """Update the heatmap JSON file with the latest threat states from the graph."""

    state = cast(CmdState, ctx.obj)
    G = state.graph

    heatmap_data = ThreatHeatMap.model_validate_json(heatmap_file.read_text())

    # check for this category the threat_id exists in the graph
    threats = get_threats_by_category(G, category)
    if not any(v.threat_id == threat_id for v in threats):
        raise ValueError(f"Threat ID '{threat_id}' not found in category '{category}'")

    heatmap_data.update_threat_state(
        category,
        threat_id,
        threat_resolution,
        applied_mitigations=applied_mitigation,
        unapplied_mitigations=unapplied_mitigation,
        notes=notes,
    )

    heatmap_file.write_text(heatmap_data.model_dump_json(indent=2))
