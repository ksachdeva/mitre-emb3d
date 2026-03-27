# Property Mapper Agent

The `[property_mapper_agent]` section controls how the AI agent maps your repository to MITRE EMB3D device properties.

## Configuration reference

```toml
[property_mapper_agent]
litellm_provider = "azure-ai"
max_token_per_analysis = 8000
extra_context = []
excluded_properties = []
excluded_categories = []
```

### `litellm_provider`

**Type:** `string` — **Required**

Name of the LLM provider to use for this agent. Must match a key defined in [`[litellm_provider.*]`](llm-providers.md).

```toml
litellm_provider = "azure-ai"
```

### `max_token_per_analysis`

**Type:** `integer` — **Default:** `16000`

Maximum number of tokens the agent may use per analysis run. Increase this for larger repositories or when you want more detailed analysis.

### `number_of_concurrent_analysis`

**Type:** `integer` — **Default:** `4`

Number of concurrent analysis tasks the agent may run in parallel. Adjust based on your system resources and provider rate limits.

```toml
number_of_concurrent_analysis = 8
```

### `extra_context`

**Type:** `list[string]` (file paths)

Paths to additional files (Markdown, text) whose content is appended to the agent's system prompt. Use this to provide project-specific knowledge that helps the agent produce better mappings.

```toml
extra_context = [
    "docs/architecture.md",
    "docs/device-overview.txt",
]
```

### `excluded_categories`

**Type:** `list[string]`

EMB3D categories to skip entirely. Useful when your device clearly doesn't fall into certain categories.

Valid values: `Hardware`, `System Software`, `Application Software`, `Networking`

```toml
excluded_categories = ["Hardware"]
```

### `excluded_properties`

**Type:** `list[string]`

Specific property IDs to exclude from analysis.

```toml
excluded_properties = ["PID-11", "PID-231"]
```

## Example

```toml
[property_mapper_agent]
litellm_provider = "azure-ai"
max_token_per_analysis = 12000
extra_context = ["docs/hw-overview.md"]
excluded_categories = ["Hardware"]
excluded_properties = ["PID-11"]
```
