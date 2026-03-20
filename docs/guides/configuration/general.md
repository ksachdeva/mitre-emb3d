# General Settings

These are the top-level keys in the configuration file.

## `output_dir`

**Type:** `string` (path)

Directory where AI artifacts (YAML files) and the generated site are written.

```toml
output_dir = "tmp"
```

The directory is created if it doesn't exist. Relative paths are resolved from the current working directory.

## `ignore`

**Type:** `list[string]`

Glob patterns for files and directories to exclude from analysis. Uses the same syntax as `.gitignore`.

```toml
ignore = [
    "tools",
    "tests",
    "build",
    "docs",
    "libraries",
    "firmware/configs",
    "README.md",
    "CONTRIBUTING.md",
]
```

!!! tip
    The tool already has built-in ignore patterns for common non-source files. Use this list for project-specific exclusions. Reducing noise helps agents produce more focused results.

## Full example

```toml
output_dir = "output"

ignore = [
    "tests",
    "docs",
    "build",
    "*.md",
]
```
