# Core Commands

These commands query the MITRE EMB3D knowledge base — categories, device properties, threats, and mitigations.

## `list-categories`

List the four EMB3D device categories.

```bash
uvx mitre-emb3d --pprint list-categories
```

**Output** — Hardware, System Software, Application Software, Networking.

---

## `list-properties-for-category`

List device properties for a category.

```bash
uvx mitre-emb3d list-properties-for-category CATEGORY [--level N]
```

| Argument / Option | Description |
|---|---|
| `CATEGORY` | One of: `Hardware`, `System Software`, `Application Software`, `Networking` |
| `--level N` | Depth of sub-properties to include (default: `1`) |

**Examples:**

```bash
uvx mitre-emb3d --pprint list-properties-for-category "Networking"
uvx mitre-emb3d --pprint list-properties-for-category "Networking" --level 3
```

---

## `list-properties-for-threat`

List device properties associated with a threat.

```bash
uvx mitre-emb3d list-properties-for-threat THREAT_ID
```

| Argument | Description |
|---|---|
| `THREAT_ID` | Threat identifier (e.g. `TID-221`) |

**Example:**

```bash
uvx mitre-emb3d --pprint list-properties-for-threat TID-221
```

---

## `list-threats-for-category`

List all threats in a category.

```bash
uvx mitre-emb3d list-threats-for-category CATEGORY
```

| Argument | Description |
|---|---|
| `CATEGORY` | One of: `Hardware`, `System Software`, `Application Software`, `Networking` |

**Example:**

```bash
uvx mitre-emb3d --pprint list-threats-for-category "Networking"
```

---

## `list-threats-for-property`

List threats for a device property.

```bash
uvx mitre-emb3d list-threats-for-property PROPERTY_ID
```

| Argument | Description |
|---|---|
| `PROPERTY_ID` | Property identifier (e.g. `PID-41`) |

**Example:**

```bash
uvx mitre-emb3d --pprint list-threats-for-property PID-41
```

---

## `list-mitigations`

List mitigations for a threat.

```bash
uvx mitre-emb3d list-mitigations THREAT_ID
```

| Argument | Description |
|---|---|
| `THREAT_ID` | Threat identifier (e.g. `TID-221`) |

**Example:**

```bash
uvx mitre-emb3d --pprint list-mitigations TID-221
```

---

## `threat`

Get detailed information about a threat, including its mitigations.

```bash
uvx mitre-emb3d threat THREAT_ID
```

| Argument | Description |
|---|---|
| `THREAT_ID` | Threat identifier (e.g. `TID-221`) |

**Example:**

```bash
uvx mitre-emb3d --pprint threat TID-221
```

---

## `mitigation`

Get detailed information about a mitigation, including associated threats.

```bash
uvx mitre-emb3d mitigation MITIGATION_ID
```

| Argument | Description |
|---|---|
| `MITIGATION_ID` | Mitigation identifier (e.g. `MID-001`) |

**Example:**

```bash
uvx mitre-emb3d --pprint mitigation MID-001
```
