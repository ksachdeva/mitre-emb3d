import asyncio
from pathlib import Path
from typing import Annotated, Optional, cast

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table
from typer import Typer

from mitre_emb3d._types import CmdState

from .config import Settings
from .property_mapper import PropertyMapper
from .repo import RepoTreeGenerator, RepoUnderReview
from .site_generator import generate_site
from .threat_analyzer import ThreatAnalyzer

ai_app = Typer(name="ai", help="AI related commands")


@ai_app.callback()
def ai(
    ctx: typer.Context,
    repo: Annotated[Path, typer.Option(help="Path to the repository", dir_okay=True, file_okay=False, exists=True)],
    config: Annotated[Path, typer.Option(help="Path to the config file", dir_okay=False, file_okay=True, exists=True)],
) -> None:
    """AI related commands for MITRE EMB3D"""
    state = cast(CmdState, ctx.obj)
    state.ai.repo = repo

    Settings._toml_file = config
    state.ai.settings = Settings()  # type: ignore


@ai_app.command()
def repo_info(
    ctx: typer.Context,
    tree_depth: Annotated[Optional[int], typer.Option(help="Depth of the tree to display")] = None,
) -> None:
    """Get the details of the repository under review"""
    state = cast(CmdState, ctx.obj)

    repo_under_review = RepoUnderReview.from_repo(state.ai.repo, state.ai.settings.ignore)

    counts = repo_under_review.extension_counts()
    table = Table(title="Files by Extension", show_lines=False)
    table.add_column("Extension", style="cyan", no_wrap=True)
    table.add_column("Count", style="green", justify="right")
    table.add_column("Bar", style="yellow")
    max_count = max(counts.values(), default=1)
    bar_width = 30
    for ext, count in counts.items():
        bar = "█" * round(count / max_count * bar_width)
        table.add_row(ext, str(count), bar)

    Console().print(table)

    # print the repo tree
    tree_generator = RepoTreeGenerator.from_repo(
        repo_under_review,
        max_level=tree_depth,
        show_token_counts=True,
    )
    rprint(tree_generator.get_tree())


@ai_app.command()
def map_properties(ctx: typer.Context) -> None:
    """Map the repository to the MITRE EMB3D Device Properties"""
    state = cast(CmdState, ctx.obj)

    repo_under_review = RepoUnderReview.from_repo(state.ai.repo, state.ai.settings.ignore)

    mapper = PropertyMapper(repo_under_review, state.graph, state.ai.settings)

    async def _run() -> None:
        await mapper.run()

    asyncio.run(_run())


@ai_app.command()
def threat_analysis(ctx: typer.Context) -> None:
    """Run threat analysis on the repository"""
    state = cast(CmdState, ctx.obj)

    repo_under_review = RepoUnderReview.from_repo(state.ai.repo, state.ai.settings.ignore)

    analyzer = ThreatAnalyzer(repo_under_review, state.graph, state.ai.settings)

    async def _run() -> None:
        await analyzer.run()

    asyncio.run(_run())


@ai_app.command()
def gen_site(ctx: typer.Context) -> None:
    """Generate a static HTML report site from the YAML artifacts"""
    state = cast(CmdState, ctx.obj)

    site_dir = generate_site(state.ai.settings.output_dir, state.graph)
    rprint(f"Site generated at: {site_dir}")
