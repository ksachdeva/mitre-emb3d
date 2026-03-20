# Installation

## Requirements

- Python 3.11 or later

## Install as a tool (recommended)

The simplest way to use `mitre-emb3d` is via [`uvx`](https://docs.astral.sh/uv/):

```bash
uvx mitre-emb3d --help
```

This downloads and runs the latest version without installing it permanently.

## Install into a project

To use `mitre-emb3d` as both a library and CLI within your project:

```bash
uv add mitre-emb3d
```

Or with pip:

```bash
pip install mitre-emb3d
```

## Verify installation

```bash
med --version
```

The CLI is available under two command names — `mitre-emb3d` and the shorter alias `med`. Both are identical.

## Shell completion

Install tab-completion for your shell:

```bash
med --install-completion
```

Or preview the completion script without installing:

```bash
med --show-completion
```
