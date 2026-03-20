import logging
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_for_filename, guess_lexer
from pygments.util import ClassNotFound
from ruamel.yaml import YAML

_LOGGER = logging.getLogger(__name__)

_TEMPLATES_PACKAGE = "mitre_emb3d.ai.site_generator"
_STATIC_DIR = Path(__file__).parent / "static"


def _highlight_code(code: str, file_name: str) -> str:
    """Syntax-highlight a code snippet, returning an HTML string."""
    try:
        lexer = get_lexer_for_filename(file_name, stripall=True)
    except ClassNotFound:
        try:
            lexer = guess_lexer(code)
        except ClassNotFound:
            return f'<div class="highlight"><pre>{code}</pre></div>'

    formatter = HtmlFormatter(nowrap=False, cssclass="highlight")
    return str(highlight(code, lexer, formatter))


def _read_yaml_dir(directory: Path) -> list[dict[str, Any]]:
    """Read all YAML files from a directory, return list of parsed dicts."""
    if not directory.exists():
        return []

    yaml = YAML()
    docs = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        with yaml_file.open() as f:
            doc = yaml.load(f)
            if doc:
                docs.append(doc)
    return docs


def _compute_property_stats(properties: list[dict[str, Any]]) -> dict[str, Any]:
    applicable = sum(1 for p in properties if p.get("is_applicable"))
    return {
        "total": len(properties),
        "applicable": applicable,
    }


def _compute_threat_stats(threats: list[dict[str, Any]]) -> dict[str, Any]:
    categories: set[str] = set()
    mitigations_total = 0
    mitigations_applied = 0

    for t in threats:
        for prop_entry in t.get("properties", {}).values():
            for m in prop_entry.get("mitigation_info", []):
                mitigations_total += 1
                if m.get("is_applied"):
                    mitigations_applied += 1

    return {
        "total": len(threats),
        "categories": list(categories),
        "mitigations_total": mitigations_total,
        "mitigations_applied": mitigations_applied,
    }


def _threat_summary(threat_doc: dict[str, Any]) -> dict[str, Any]:
    """Augment a threat doc with computed summary fields for the index page."""
    mitigations_total = 0
    mitigations_applied = 0
    for prop_entry in threat_doc.get("properties", {}).values():
        for m in prop_entry.get("mitigation_info", []):
            mitigations_total += 1
            if m.get("is_applied"):
                mitigations_applied += 1

    return {
        **threat_doc,
        "mitigations_total": mitigations_total,
        "mitigations_applied": mitigations_applied,
    }


def _group_properties_by_category(properties: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for prop in properties:
        category = prop.get("category", "Unknown")
        grouped[category].append(prop)
    return dict(grouped)


def _find_related_threats(property_id: str, threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find threats that reference a given property_id."""
    related = []
    for t in threats:
        if property_id in t.get("properties", {}):
            related.append({"threat_id": t["threat_id"], "threat_name": t["threat_name"]})
    return related


def generate_site(output_dir: Path) -> Path:
    """Generate a static HTML site from the YAML artifacts in output_dir.

    Reads from:
        output_dir/properties/*.yaml
        output_dir/threats/*.yaml

    Writes to:
        output_dir/site/

    Returns the path to the generated site directory.
    """
    site_dir = output_dir / "site"
    site_dir.mkdir(parents=True, exist_ok=True)

    # Read artifacts
    properties = _read_yaml_dir(output_dir / "properties")
    threats = _read_yaml_dir(output_dir / "threats")

    _LOGGER.info(f"Read {len(properties)} property docs, {len(threats)} threat docs")

    # Set up Jinja2
    env = Environment(
        loader=PackageLoader(_TEMPLATES_PACKAGE, "templates"),
        autoescape=select_autoescape(["html"]),
    )

    # Compute stats
    property_stats = _compute_property_stats(properties)
    threat_stats = _compute_threat_stats(threats)

    # Prepare threat summaries for index
    threat_summaries = [_threat_summary(t) for t in threats]
    properties_by_category = _group_properties_by_category(properties)

    # --- Render index ---
    index_tmpl = env.get_template("index.html")
    index_html = index_tmpl.render(
        root_path="",
        property_stats=property_stats,
        threat_stats=threat_stats,
        properties_by_category=properties_by_category,
        threats=threat_summaries,
    )
    (site_dir / "index.html").write_text(index_html)
    _LOGGER.info("Wrote index.html")

    # --- Render property pages ---
    prop_dir = site_dir / "properties"
    prop_dir.mkdir(exist_ok=True)
    prop_tmpl = env.get_template("property.html")

    for prop in properties:
        # Highlight code snippets
        enriched_evidence = []
        for ev in prop.get("evidence", []):
            highlighted = _highlight_code(str(ev.get("code_snippet", "")), ev.get("file_name", ""))
            enriched_evidence.append({**ev, "highlighted_code": highlighted})

        related_threats = _find_related_threats(prop["property_id"], threats)

        html = prop_tmpl.render(
            root_path="../",
            doc={**prop, "evidence": enriched_evidence},
            related_threats=related_threats,
        )
        (prop_dir / f"{prop['property_id']}.html").write_text(html)

    _LOGGER.info(f"Wrote {len(properties)} property pages")

    # --- Render threat pages ---
    threats_dir = site_dir / "threats"
    threats_dir.mkdir(exist_ok=True)
    threat_tmpl = env.get_template("threat.html")

    for threat_doc in threats:
        html = threat_tmpl.render(
            root_path="../",
            doc=threat_doc,
        )
        (threats_dir / f"{threat_doc['threat_id']}.html").write_text(html)

    _LOGGER.info(f"Wrote {len(threats)} threat pages")

    # --- Copy static assets ---
    static_dest = site_dir / "static"
    if static_dest.exists():
        shutil.rmtree(static_dest)
    shutil.copytree(_STATIC_DIR, static_dest)
    _LOGGER.info("Copied static assets")

    return site_dir
