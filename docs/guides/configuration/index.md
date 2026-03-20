# Configuration Guide

The AI commands (`map-properties`, `threat-analysis`, `gen-site`) are driven by a TOML configuration file passed via `--config`. This guide walks through every section of the file.

## Minimal example

```toml
output_dir = "output"

ignore = ["tests", "docs"]

[property_mapper_agent]
litellm_provider = "my-provider"

[threat_analyzer_agent]
litellm_provider = "my-provider"

[litellm_provider.my-provider]
model_name = "ollama_chat/devstral-small-2:24b"
provider_args = { api_key = "ollama", api_base = "http://localhost:11434" }
```

## File structure

The config file has four top-level areas:

| Section | Purpose |
|---|---|
| [General settings](general.md) | Output directory and ignore patterns |
| [`[property_mapper_agent]`](property-mapper.md) | Property Mapper agent behavior |
| [`[threat_analyzer_agent]`](threat-analyzer.md) | Threat Analyzer agent behavior |
| [`[litellm_provider.*]`](llm-providers.md) | LLM provider definitions |

## Sections

- **[General Settings](general.md)** — `output_dir`, `ignore`
- **[Property Mapper Agent](property-mapper.md)** — Control which properties are analyzed and how
- **[Threat Analyzer Agent](threat-analyzer.md)** — Control which threats are analyzed and how
- **[LLM Providers](llm-providers.md)** — Define the models your agents use
