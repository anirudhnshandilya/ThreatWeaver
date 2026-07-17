# ThreatWeaver

> **From Infrastructure-as-Code to evidence-backed attack paths.**

ThreatWeaver is an open-source security graph engine that transforms cloud infrastructure into explainable attack paths.

Instead of simply identifying individual misconfigurations, ThreatWeaver models how attackers move through cloud environments using network reachability, identity relationships, privilege analysis, and trust boundaries.

Every finding includes transparent evidence, explainable risk scoring, MITRE ATT&CK mappings, and actionable remediation guidance.

> 🚧 **Project Status:** Early Development (90-Day Public Build)

---

## Why ThreatWeaver?

Modern cloud environments are rarely compromised because of a single vulnerability.

Real attacks are chains.

For example:

```
Internet
    │
    ▼
Public Load Balancer
    │
    ▼
EC2 Instance
    │
    ▼
IAM Role
    │
    ▼
Secrets Manager
    │
    ▼
Production Database
```

Traditional security scanners report each issue independently.

ThreatWeaver connects these relationships into complete attack paths, helping security engineers understand **how an attacker can actually move through an environment**, not just what individual resources are misconfigured.

---

# Features

- Infrastructure-as-Code analysis
- Terraform support (v0.1)
- Kubernetes support (planned)
- AWS security graph generation
- Attack path discovery
- Network reachability analysis
- Identity & privilege analysis
- Trust boundary modelling
- MITRE ATT&CK mapping
- STRIDE classification
- Evidence-backed findings
- Transparent risk scoring
- Confidence scoring
- JSON reports
- SARIF reports
- HTML reports
- Mermaid diagrams
- Graphviz diagrams
- Extensible rule engine
- Local-first architecture
- Optional AI-powered explanations

---

# Architecture

```
                    Infrastructure-as-Code
                (Terraform / Kubernetes YAML)
                              │
                              ▼
                     Infrastructure Parser
                              │
                              ▼
                 Normalized Resource Model
                              │
                              ▼
                    Security Graph Engine
                              │
                              ▼
                    Security Rule Engine
                              │
                              ▼
                  Attack Path Discovery Engine
                              │
                              ▼
              Risk & Confidence Scoring Engine
                              │
                              ▼
       Reports • MITRE • STRIDE • Visualizations
```

---

# Example

```bash
tw scan examples/terraform/vulnerable-web-app
```

Output

```text
──────────────────────────────────────────────
ThreatWeaver Scan Summary
──────────────────────────────────────────────

Resources Analysed: 42
Critical Findings: 2
High Findings: 5

Critical Attack Path

Internet
      │
      ▼
Application Load Balancer
      │
      ▼
EC2 Instance
      │
      ▼
IAM Role
      │
      ▼
Secrets Manager
      │
      ▼
Production Database Credentials
```

---

# Example Finding

```text
Finding ID

TW-PATH-001

Severity

Critical

Attack Path

Internet
 ↓
Public ALB
 ↓
EC2
 ↓
IAM Role
 ↓
Secrets Manager

Risk Score

9.1 / 10

Confidence

96%

MITRE ATT&CK

T1190
T1078
T1552

Evidence

main.tf               line 52
security_groups.tf    line 19
iam.tf                line 83

Recommended Actions

• Remove wildcard IAM permissions
• Restrict Security Group ingress
• Apply least privilege
• Enable workload isolation
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/anirudhnshandilya/ThreatWeaver.git
```

Move into the project

```bash
cd ThreatWeaver
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate

Windows

```bash
.venv\Scripts\activate
```

Linux/macOS

```bash
source .venv/bin/activate
```

Install

```bash
pip install -e ".[dev]"
```

---

# Quick Start

Run

```bash
tw scan path/to/infrastructure
```

Generate JSON

```bash
tw report --format json
```

Generate HTML

```bash
tw report --format html
```

Generate SARIF

```bash
tw report --format sarif
```

---

# Project Structure

```
ThreatWeaver/

├── docs/
├── examples/
├── scripts/
├── src/
│   └── threatweaver/
├── tests/
├── .github/
├── ROADMAP.md
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── LICENSE
└── pyproject.toml
```

---

# Roadmap

## v0.1

- Terraform Parser
- AWS Resource Graph
- CLI
- Resource Relationships

---

## v0.5

- Attack Path Discovery
- Risk Scoring
- Confidence Scoring
- MITRE ATT&CK Mapping
- STRIDE Classification
- JSON Reports
- HTML Reports
- SARIF Reports

---

## v1.0

- Kubernetes Support
- Interactive Graph Visualization
- FastAPI Service
- GitHub Action
- Documentation Website
- Stable Release

---

## Future Vision

ThreatWeaver aims to become the open-source standard for infrastructure attack-path analysis.

By combining deterministic graph analysis with explainable security reasoning, it helps engineers understand **not just what is vulnerable, but exactly how attackers can exploit multiple weaknesses to reach critical assets.**

AI is used only as an optional explanation layer.

Security findings are always generated using deterministic graph analysis and transparent security rules.

---

# Documentation

- Architecture
- Graph Model
- Rule Engine
- Roadmap
- Contributing Guide

---

# Contributing

Contributions are welcome.

Whether you're improving parsers, adding cloud providers, creating security rules, fixing bugs, improving documentation, or enhancing reports, we'd love your help.

Please read **CONTRIBUTING.md** before opening a Pull Request.

---

# Principles

ThreatWeaver is built around five core principles.

- Deterministic security analysis
- Evidence attached to every finding
- Explainable risk scoring
- Local-first execution
- Extensible architecture

---

# Tech Stack

### Core

- Python
- Typer
- Rich
- Pydantic
- NetworkX

### Security

- Terraform
- Kubernetes
- MITRE ATT&CK
- STRIDE

### Reports

- JSON
- HTML
- SARIF
- Mermaid
- Graphviz

### Future

- FastAPI
- React
- Cytoscape.js
- Ollama
- Neo4j

---

# License

Licensed under the Apache License 2.0.

---

# Author

**Anirudh N Shandilya**

Building ThreatWeaver publicly over 90 days to advance open-source cloud security and attack-path analysis.
