import logging
from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint
from typer import Typer

from mitre_emb3d import __version__
from mitre_emb3d._doc_loaders import from_release
from mitre_emb3d._graph import build_split_graph, write_graphml
from mitre_emb3d._locations import cache_directory
from mitre_emb3d._models import StixBundle as ST
from mitre_emb3d._types import CmdState

_LOGGER = logging.getLogger(__name__)

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


cli_app = Typer(name=f"MITRE EMB3D Client [{__version__}]")


@cli_app.callback()
def main(
    ctx: typer.Context,
    release: Annotated[
        str,
        typer.Option(
            help="2.0.1, 2.0 ...",
        ),
    ] = "2.0.1",
    loglevel: Annotated[
        str,
        typer.Option(
            "--loglevel",
            "-l",
            help="Set the logging level (debug, info, warning, error, critical)",
        ),
    ] = "warning",
    cache: Annotated[bool, typer.Option(help="Whether to cache the emb3d-stix.json file for future use")] = True,
) -> None:
    logging.basicConfig(level=LOG_LEVELS.get(loglevel, logging.WARNING))
    logging.getLogger("mitre_emb3d").setLevel(LOG_LEVELS.get(loglevel, logging.WARNING))

    # cache file_name
    file_name = cache_directory().joinpath(f"emb3d-stix-{release}.json")

    if file_name.exists() and cache:
        _LOGGER.info(f"Loading emb3d-stix-{release}.json from cache ...")
        bundle_doc = ST.model_validate_json(file_name.read_text())
    else:
        bundle_doc = from_release(release)
        file_name.write_text(bundle_doc.model_dump_json())

    ctx.ensure_object(CmdState)
    ctx.obj = CmdState()
    ctx.obj.doc = bundle_doc
    ctx.obj.graph = build_split_graph(bundle_doc)

    rprint(bundle_doc.objects[224].model_dump_json(indent=2))


@cli_app.command()
def categories(ctx: typer.Context) -> None:
    "List the categories"
    write_graphml(ctx.obj.graph, Path("emb3d.graphml"))
