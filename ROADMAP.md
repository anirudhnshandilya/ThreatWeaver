# ThreatWeaver Roadmap

ThreatWeaver is being developed through a 90-day public build focused on deterministic, evidence-backed attack-path analysis.

## Phase 1 — Foundation

- Repository setup
- Python package structure
- CLI foundation
- Code quality tooling
- Documentation structure
- Continuous integration

## Phase 2 — Infrastructure Parsing

- Terraform plan JSON ingestion
- AWS resource normalisation
- Source-file evidence tracking
- Resource relationship extraction

## Phase 3 — Security Graph Engine

- Resource nodes
- Network relationships
- Identity relationships
- Trust boundaries
- Sensitive asset classification

## Phase 4 — Security Analysis

- Exposure detection
- IAM privilege analysis
- Network reachability
- Attack-path discovery
- Risk scoring
- Confidence scoring

## Phase 5 — Intelligence and Reporting

- MITRE ATT&CK mapping
- STRIDE classification
- JSON reports
- SARIF reports
- HTML reports
- Mermaid and Graphviz diagrams

## Phase 6 — Kubernetes and Explanations

- Kubernetes manifest parsing
- RBAC analysis
- Kubernetes attack paths
- Local Ollama explanations
- Optional hosted-model support

## Phase 7 — Productisation

- FastAPI service
- Interactive web interface
- GitHub Action
- Docker image
- Plugin system
- Benchmark and evaluation suite

## Version Milestones

### v0.1

Terraform-defined AWS resource graph and initial CLI output.

### v0.5

Attack-path discovery, risk scoring, MITRE mapping, and reporting.

### v1.0

Terraform and Kubernetes analysis, interactive visualisation, CI integration, documentation, and stable release.
