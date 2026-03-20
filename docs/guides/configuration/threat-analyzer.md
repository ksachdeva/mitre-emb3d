# Threat Analyzer Agent

The `[threat_analyzer_agent]` section controls how the AI agent evaluates threats and mitigations for your repository.

## Configuration reference

```toml
[threat_analyzer_agent]
litellm_provider = "azure-ai"
max_token_per_analysis = 8000
extra_context = []
excluded_threats = []
```

### `litellm_provider`

**Type:** `string` — **Required**

Name of the LLM provider to use for this agent. Must match a key defined in [`[litellm_provider.*]`](llm-providers.md).

```toml
litellm_provider = "azure-ai"
```

### `max_token_per_analysis`

**Type:** `integer` — **Default:** `8000`

Maximum number of tokens the agent may use per analysis run.

```toml
max_token_per_analysis = 16000
```

### `extra_context`

**Type:** `list[string]` (file paths)

Paths to additional files whose content is appended to the agent's system prompt. Provide threat modeling context, prior assessments, or architecture documents to improve results.

```toml
extra_context = [
    "docs/threat-model-notes.md",
]
```

### `excluded_threats`

**Type:** `list[string]`

Specific threat IDs to exclude from analysis. Use this to skip threats that are known to be irrelevant.

```toml
excluded_threats = ["TID-110", "TID-222"]
```

## Example

```toml
[threat_analyzer_agent]
litellm_provider = "gh-copilot-sonnet"
max_token_per_analysis = 10000
extra_context = ["docs/security-assessment.md"]
excluded_threats = ["TID-110"]
```
