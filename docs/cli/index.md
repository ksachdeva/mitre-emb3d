# CLI Reference

The `mitre-emb3d` CLI (aliased as `med`) provides access to the full MITRE EMB3D framework from the command line.

```
med [OPTIONS] COMMAND [ARGS]...
```

## Command groups

| Group | Description |
|---|---|
| [Core Commands](core-commands.md) | Query categories, properties, threats, and mitigations |
| [Heatmap Commands](heatmap-commands.md) | Initialize and manage threat assessment heatmaps |
| [AI Commands](ai-commands.md) | AI-powered property mapping, threat analysis, and report generation |
| [MCP Server](mcp-server.md) | Launch the Model Context Protocol server |

## Output modes

By default, all commands output **JSON** — designed for piping into other tools or AI agents.

Add `--pprint` for human-readable formatted output:

```bash
med --pprint list-categories
```

See [Global Options](global-options.md) for all top-level flags.
