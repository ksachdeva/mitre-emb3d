# LLM Providers

The `[litellm_provider.*]` sections define the LLM models available for agents. Each provider is given a name that agents reference via their `litellm_provider` setting.

Provider configuration uses [LiteLLM](https://docs.litellm.ai/) under the hood, so any model supported by LiteLLM can be used.

## Configuration reference

```toml
[litellm_provider.NAME]
model_name = "provider/model"
provider_args = { ... }
```

### `model_name`

**Type:** `string` — **Required**

The LiteLLM model identifier. Format is typically `provider/model-name`.

### `provider_args`

**Type:** `object` — **Default:** `{}`

Provider-specific arguments such as API keys and endpoints. What keys are needed depends on the provider.

!!! warning
    Avoid putting API keys directly in the config file if it will be committed to source control. Use environment variables instead — LiteLLM reads provider-specific environment variables automatically.

## Provider examples

### Ollama (local)

```toml
[litellm_provider.ollama-local]
model_name = "ollama_chat/devstral-small-2:24b"
provider_args = { api_key = "ollama", api_base = "http://localhost:11434" }
```

### GitHub Copilot

```toml
[litellm_provider.gh-copilot-sonnet]
model_name = "github_copilot/claude-sonnet-4.6"
```

On first use you will be prompted to verify a code in your browser and a token will be stored locally.

### Azure OpenAI

```toml
[litellm_provider.azure-openai]
model_name = "azure/gpt-4.1"
provider_args = { api_key = "", api_base = "", api_version = "2024-12-01-preview" }
```

Environment variables: `AZURE_API_KEY`, `AZURE_API_BASE`. See the [LiteLLM Azure docs](https://docs.litellm.ai/docs/providers/azure/).

### Azure AI Inference

```toml
[litellm_provider.azure-ai]
model_name = "azure_ai/gpt-5.3-codex"
provider_args = { api_key = "", api_base = "", api_version = "2025-04-01-preview" }
```

Environment variables: `AZURE_AI_API_KEY`, `AZURE_AI_API_BASE`. See the [LiteLLM Azure AI docs](https://docs.litellm.ai/docs/providers/azure_ai).

### OpenAI-compatible servers (llama.cpp, local OpenAI-like endpoints)

This mode is used for providers that expose an OpenAI-compatible API

```toml
[litellm_provider.prov-3]
model_name = "openai/Qwen3-8B-GGUF"
provider_args = { api_key = "bogus", api_base = "http://host.docker.internal:8080" }
```

- `model_name` uses the `openai/` prefix for LiteLLM compatibility.
- `provider_args.api_key` is typically set from env var `OPENAI_API_KEY` for real credentials.
- `provider_args.api_base` points to the OpenAI-compatible endpoint in your local/network setup.

Example with environment-backed security (recommended):

```toml
[litellm_provider.prov-3]
model_name = "openai/Qwen3-8B-GGUF"
provider_args = { api_key = "", api_base = "http://host.docker.internal:8080" }
```

And set (or export) `OPENAI_API_KEY` before running the tool.

## Using multiple providers

You can define as many providers as you need and assign different ones to different agents:

```toml
[property_mapper_agent]
litellm_provider = "ollama-local"

[threat_analyzer_agent]
litellm_provider = "azure-ai"

[litellm_provider.ollama-local]
model_name = "ollama_chat/devstral-small-2:24b"
provider_args = { api_key = "ollama", api_base = "http://localhost:11434" }

[litellm_provider.azure-ai]
model_name = "azure_ai/gpt-5.3-codex"
provider_args = { api_key = "", api_base = "" }

[litellm_provider.prov-3]
model_name = "openai/Qwen3-8B-GGUF"
provider_args = { api_key = "bogus", api_base = "http://localhost:8080" }

```
