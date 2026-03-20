# AI Commands

AI commands use LLM agents to analyze a repository against the MITRE EMB3D framework. All AI commands live under the `ai` subcommand and require `--repo` and `--config` options.

```bash
uvx mitre-emb3d ai --repo PATH --config PATH COMMAND
```

| Option | Description |
|---|---|
| `--repo PATH` | Path to the repository to analyze |
| `--config PATH` | Path to the TOML [configuration file](../guides/configuration/index.md) |

See the [Configuration Guide](../guides/configuration/index.md) for how to set up the config file.

---

## `ai repo-info`

Display repository details — file extension distribution and a tokenized directory tree.

```bash
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml repo-info [--tree-depth N]
```

| Option | Description |
|---|---|
| `--tree-depth N` | Maximum depth of the directory tree to display (optional) |

This is useful for understanding the shape of a repository before running analysis, and for verifying that your `ignore` patterns in the config are filtering out unwanted files.

**Example:**

```bash
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml repo-info --tree-depth 3
```

---

## `ai map-properties`

Map the repository's codebase to MITRE EMB3D device properties using an AI agent.

```bash
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml map-properties
```

The PropertyMapper agent scans the repository, analyzes source files, and identifies which EMB3D device properties are relevant. Results are written as YAML artifacts to the configured `output_dir`.

The agent behavior is controlled by the `[property_mapper_agent]` section of the config file. See [Property Mapper Agent configuration](../guides/configuration/property-mapper.md).

---

## `ai threat-analysis`

Run threat analysis on the repository using an AI agent.

```bash
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml threat-analysis
```

The ThreatAnalyzer agent takes the property mappings and evaluates which threats apply and what mitigations are relevant. Results are written as YAML artifacts to the configured `output_dir`.

!!! note
    Run `map-properties` before `threat-analysis` — the threat analyzer uses the property mapping output as input.

The agent behavior is controlled by the `[threat_analyzer_agent]` section of the config file. See [Threat Analyzer Agent configuration](../guides/configuration/threat-analyzer.md).

---

## `ai gen-site`

Generate a static HTML report site from the YAML artifacts produced by `map-properties` and `threat-analysis`.

```bash
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml gen-site
```

The site is generated in the `output_dir` specified in your config file, under a `site/` subdirectory.

---

## Typical workflow

A full AI analysis workflow:

```bash
# 1. Inspect the repo structure
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml repo-info

# 2. Map the codebase to EMB3D device properties
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml map-properties

# 3. Run threat analysis
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml threat-analysis

# 4. Generate the HTML report
uvx mitre-emb3d ai --repo ./my-firmware --config config.toml gen-site
```
