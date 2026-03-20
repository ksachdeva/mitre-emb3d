# Core Commands

These commands query the MITRE EMB3D knowledge base — categories, device properties, threats, and mitigations.

## `list-categories`

List the four EMB3D device categories.

```bash
med --pprint list-categories
```

**Output** — Hardware, System Software, Application Software, Networking.

---

## `list-properties-for-category`

List device properties for a category.

```bash
med list-properties-for-category CATEGORY [--level N]
```

| Argument / Option | Description |
|---|---|
| `CATEGORY` | One of: `Hardware`, `System Software`, `Application Software`, `Networking` |
| `--level N` | Depth of sub-properties to include (default: `1`) |

**Examples:**

```bash
med --pprint list-properties-for-category "Networking"
med --pprint list-properties-for-category "Networking" --level 3
```

---

## `list-properties-for-threat`

List device properties associated with a threat.

```bash
med list-properties-for-threat THREAT_ID
```

| Argument | Description |
|---|---|
| `THREAT_ID` | Threat identifier (e.g. `TID-221`) |

**Example:**

```bash
med --pprint list-properties-for-threat TID-221
```

---

## `list-threats-for-category`

List all threats in a category.

```bash
med list-threats-for-category CATEGORY
```

| Argument | Description |
|---|---|
| `CATEGORY` | One of: `Hardware`, `System Software`, `Application Software`, `Networking` |

**Example:**

```bash
med --pprint list-threats-for-category "Networking"
```

---

## `list-threats-for-property`

List threats for a device property.

```bash
med list-threats-for-property PROPERTY_ID
```

| Argument | Description |
|---|---|
| `PROPERTY_ID` | Property identifier (e.g. `PID-41`) |

**Example:**

```bash
med --pprint list-threats-for-property PID-41
```

---

## `list-mitigations`

List mitigations for a threat.

```bash
med list-mitigations THREAT_ID
```

| Argument | Description |
|---|---|
| `THREAT_ID` | Threat identifier (e.g. `TID-221`) |

**Example:**

```bash
med --pprint list-mitigations TID-221
```

---

## `threat`

Get detailed information about a threat, including its mitigations.

```bash
med threat THREAT_ID
```

| Argument | Description |
|---|---|
| `THREAT_ID` | Threat identifier (e.g. `TID-221`) |

**Example:**

```bash
med --pprint threat TID-221
```

---

## `mitigation`

Get detailed information about a mitigation, including associated threats.

```bash
med mitigation MITIGATION_ID
```

| Argument | Description |
|---|---|
| `MITIGATION_ID` | Mitigation identifier (e.g. `MID-001`) |

**Example:**

```bash
med --pprint mitigation MID-001
```
