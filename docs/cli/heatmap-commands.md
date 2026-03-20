# Heatmap Commands

Heatmap commands let you initialize and manage threat assessment tracking for a project. All heatmap commands live under the `heatmap` subcommand.

```bash
med heatmap COMMAND [ARGS]...
```

Heatmap data is stored as JSON in `~/.local/share/mitre-emb3d/` by default. Override the storage directory with the environment variable:

```bash
export MITRE_EMB3D_HEATMAP_JSON_STORAGE_DIR=/path/to/dir
```

---

## `heatmap init`

Initialize a heatmap for a project. All threats start with the status `NOT_INVESTIGATED`.

```bash
med heatmap init PROJECT_NAME DESCRIPTION
```

| Argument | Description |
|---|---|
| `PROJECT_NAME` | Name of the project |
| `DESCRIPTION` | Short description of the project |

**Example:**

```bash
med heatmap init my-device "IoT gateway firmware"
```

---

## `heatmap read`

Read threat assessment entries for a category.

```bash
med heatmap read PROJECT_NAME CATEGORY
```

| Argument | Description |
|---|---|
| `PROJECT_NAME` | Name of the project |
| `CATEGORY` | One of: `Hardware`, `System Software`, `Application Software`, `Networking` |

**Example:**

```bash
med --pprint heatmap read my-device "Networking"
```

---

## `heatmap update-threat-status`

Update the assessment status of a threat.

```bash
med heatmap update-threat-status PROJECT_NAME CATEGORY THREAT_ID [--tr STATUS]
```

| Argument / Option | Description |
|---|---|
| `PROJECT_NAME` | Name of the project |
| `CATEGORY` | Category the threat belongs to |
| `THREAT_ID` | Threat identifier (e.g. `TID-221`) |
| `--tr STATUS` | Threat resolution state |

---

## `heatmap update-mitigation-status`

Update the status of a mitigation within a threat.

```bash
med heatmap update-mitigation-status PROJECT_NAME CATEGORY THREAT_ID MITIGATION_ID [--mr STATUS]
```

| Argument / Option | Description |
|---|---|
| `PROJECT_NAME` | Name of the project |
| `CATEGORY` | Category the threat belongs to |
| `THREAT_ID` | Threat identifier |
| `MITIGATION_ID` | Mitigation identifier |
| `--mr STATUS` | Mitigation resolution state |
