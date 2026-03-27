# MCP Server

Launch a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that exposes all MITRE EMB3D functionality as tools for AI assistants.

```bash
uvx mitre-emb3d mcp
```

## Exposed tools

The MCP server exposes the following tools:

| Tool | Description |
|---|---|
| `get_categories()` | List all EMB3D categories |
| `get_properties_for_category(category, level)` | Properties for a category with sub-property depth |
| `get_properties_for_threat(threat_id)` | Properties associated with a threat |
| `get_threats_for_category(category)` | Threats in a category |
| `get_threats_for_property(property_id)` | Threats for a device property |
| `get_mitigations(threat_id)` | Mitigations for a threat |
| `get_threat(threat_id)` | Threat details with mitigations |
| `get_mitigation(mitigation_id)` | Mitigation details with threats |

## Usage with AI assistants

Add the MCP server to your AI assistant configuration. For example, in a VS Code MCP config:

```json
{
  "servers": {
    "mitre-emb3d": {
      "command": "uvx",
      "args": ["mitre-emb3d", "mcp"]
    }
  }
}
```
