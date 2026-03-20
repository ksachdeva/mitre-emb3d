# Global Options

These options are available on every command and must be placed **before** the subcommand name.

```
uvx mitre-emb3d [OPTIONS] COMMAND [ARGS]...
```

## Options

### `--version`

Show the version and exit.

```bash
uvx mitre-emb3d --version
```

### `--release TEXT`

MITRE EMB3D release version to use. Defaults to `2.0.1`.

```bash
uvx mitre-emb3d --release 2.0.1 list-categories
```

### `--heatmap-storage [json]`

Storage backend for heatmaps. Currently only `json` is supported.

### `--loglevel`, `-l TEXT`

Set the logging level. One of: `debug`, `info`, `warning`, `error`, `critical`.

Defaults to `warning`.

```bash
uvx mitre-emb3d -l debug list-categories
```

### `--pprint` / `--no-pprint`

Toggle pretty-printed output. Default is `--no-pprint` which outputs raw JSON.

```bash
uvx mitre-emb3d --pprint list-threats-for-category "Networking"
```

### `--install-completion`

Install shell tab-completion for your current shell.

### `--show-completion`

Print the completion script to stdout without installing it.
