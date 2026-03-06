# MITRE EMB3D

A CLI for https://emb3d.mitre.org/

## Run

### Via `uvx`

```bash
uvx mitre-emb3d --help
```

or

```bash
uvx --from mitre-emb3d med --help
uvx --from mitre-emb3d med --pprint properties Networking --level 3
```

### Install as a tool

```bash
uv tool install mitre-emb3d
```

## Add to your project

```bash
uv add mitre-emb3d --dev
```

and then run the cli via

```bash
uv run med --help
```

or

```bash
uv run mitre-emb3d --help
```

## Features

```bash
$ uv run med --pprint threats "Networking"
- TID-221: Authentication Bypass By Message Replay
- TID-222: Critical System Service May Be Disabled
- TID-310: Remotely Accessible Unauthenticated Services
- TID-316: Incorrect Certificate Verification Allows Authentication Bypass
- TID-317: Predictable Cryptographic Key
- TID-318: Insecure Cryptographic Implementation
- TID-401: Undocumented Protocol Features
- TID-404: Remotely Triggerable Deadlock/DoS
- TID-405: Network Stack Resource Exhaustion
- TID-406: Unauthorized Messages or Connections
- TID-407: Missing Message Replay Protection
- TID-408: Unencrypted Sensitive Data Communication
- TID-410: Cryptographic Protocol Side Channel
- TID-411: Weak/Insecure Cryptographic Protocol
- TID-412: Network Routing Capability Abuse
```

***Explore other commands using the CLI help***

> Note --pprint (default is OFF, default output is JSON) for display


```markdown
uv run med --help

Usage: med [OPTIONS] COMMAND [ARGS]...

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --release                                TEXT  2.0.1, 2.0 ... [default: 2.0.1]                                                                                                           │
│ --loglevel            -l                 TEXT  Set the logging level (debug, info, warning, error, critical) [default: warning]                                                          │
│ --pprint                  --no-pprint          Whether to pretty-print the output (e.g. JSON lists) [default: no-pprint]                                                                 │
│ --install-completion                           Install completion for the current shell.                                                                                                 │
│ --show-completion                              Show completion for the current shell, to copy it or customize the installation.                                                          │
│ --help                                         Show this message and exit.                                                                                                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ categories   List the categories                                                                                                                                                         │
│ properties   List properties for a certain category                                                                                                                                      │
│ threats      List threats for a certain category                                                                                                                                         │
│ mitigations  List mitigations for a certain threat                                                                                                                                       │
│ heatmap      Heatmap related commands                                                                                                                                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```
