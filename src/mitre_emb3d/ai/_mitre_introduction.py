MITRE_INTRODUCTION = """

## EMB3D™ Threat Model

Threat model for embedded devices across critical infrastructure, IoT, automotive, healthcare, and manufacturing.
Maps known threats to device properties so users can enumerate threat exposure based on device features.
Audience: vendors, asset owners, testers, and security researchers.

### Device Properties

Describe hardware/software components and capabilities of a device. Categories:

- **Hardware Architecture**: Processors, memory, storage, FPGAs, board-level components, physical interfaces (console, serial, USB) and debug interfaces (JTAG, UART).
- **System Software**: OS, firmware, update mechanisms (e.g., OTA updates).
- **Application Software**: Web servers, runtime environments, programmability features implementing device-specific services.
- **Networking**: Network hardware (Ethernet, Bluetooth) and protocols (OPC UA, CAN bus).

Categories subdivide into sub-properties mapped to threats.
Mappings indicate relevant threats per property — not exhaustive preconditions, but sufficient to distinguish the most relevant threats.

### Threats

Threats map to device properties and describe how an actor achieves an objective on a device. Each threat includes:

- **Threat ID**: Unique identifier (format: `TID-###`).
- **Overview**: Short description.
- **Description**: Targeted mechanisms, required threat actions and impact, and enabling weaknesses.
- **Maturity & Evidence**:
  - *Maturity levels*: Observed Adversarial Technique | Known Exploitable Weakness (KEV) | Proof of Concept | Theoretic
  - *Evidence*: ATT&CK TTPs or documented reports (Observed); CWE+KEV documentation (KEV); research papers (PoC/Theoretic)
- **Weaknesses**: Mapped CWE at lowest feasible abstraction (Variant/Base preferred over Pillar/Class).
- **Vulnerabilities**: Example CVEs of the weakness in embedded devices (where available).

### Mitigations

High-level, non-prescriptive mechanisms/technologies that protect against threats.
Intended for vendors (risk reduction) and end users (validation).

Each mitigation includes:

- **Description**: How it mitigates the threat.
- **References**: Published implementation guidance.
- **Tier**: Implementation maturity/difficulty level (see below).

#### Tiers

| Tier | Name | Description |
|------|------|-------------|
| 0 | Foundational | Minimal viable mitigation; proven feasible on embedded devices; well-defined implementation guidelines; no dedicated hardware or proprietary dependencies. |
| 1 | Intermediate | Commercially adopted in other domains (IT, mobile) but lacking embedded-specific guidance; may require hardware/design changes or proprietary technology integration. |
| 2 | Leading | Most robust; includes novel research, PoCs, or limited deployments; may lack mature guidance; requires significant R&D. |

"""
