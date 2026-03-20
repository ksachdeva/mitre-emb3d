# Quick Start

This guide walks you through the basic CLI commands to explore the MITRE EMB3D framework.

## Explore categories

List the four EMB3D device categories:

```bash
med --pprint list-categories
```

## List properties

View device properties for a category:

```bash
med --pprint list-properties-for-category "Networking"
```

Include sub-properties up to a given depth:

```bash
med --pprint list-properties-for-category "Networking" --level 3
```

## List threats

See all threats in a category:

```bash
med --pprint list-threats-for-category "Networking"
```

Or threats related to a specific property:

```bash
med --pprint list-threats-for-property PID-41
```

## Get threat details

View a threat along with its mitigations:

```bash
med --pprint threat TID-221
```

## AI-powered analysis

To run AI analysis on a repository, you need a [configuration file](../guides/configuration/index.md):

```bash
med ai --repo ./my-firmware --config config.toml map-properties
med ai --repo ./my-firmware --config config.toml threat-analysis
med ai --repo ./my-firmware --config config.toml gen-site
```

See the [AI Commands](../cli/ai-commands.md) reference and the [Configuration Guide](../guides/configuration/index.md) for details.
