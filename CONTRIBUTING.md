# Contributing to ThreatWeaver

Thank you for your interest in contributing to ThreatWeaver.

ThreatWeaver is an open-source infrastructure security graph engine that transforms Infrastructure-as-Code into deterministic, evidence-backed attack paths.

Contributions involving code, security rules, documentation, testing, examples, research, and design are welcome.

## Ways to Contribute

You can contribute by:

* Reporting bugs
* Suggesting features
* Improving documentation
* Adding Terraform resource support
* Adding cloud-provider parsers
* Creating security detection rules
* Improving attack-path analysis
* Adding tests and infrastructure examples
* Improving reports and visualizations
* Reviewing issues and pull requests
* Improving performance, reliability, or usability

## Before Contributing

Before starting substantial work:

1. Search existing issues and pull requests.
2. Check the project roadmap.
3. Open an issue describing the proposed change.
4. Wait for agreement before making a large architectural change.

Small corrections, tests, and documentation improvements may be submitted directly.

## Development Setup

Clone the repository:

```bash
git clone https://github.com/anirudhnshandilya/ThreatWeaver.git
cd ThreatWeaver
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Install the project and development dependencies:

```bash
pip install -e ".[dev]"
```

Install the pre-commit hooks:

```bash
pre-commit install
```

## Development Workflow

Do not make feature changes directly on `main`.

Create a branch from the latest version of `main`:

```bash
git checkout main
git pull origin main
git checkout -b feature/short-description
```

Recommended branch prefixes include:

```text
feature/
fix/
docs/
test/
refactor/
security/
```

Examples:

```text
feature/aws-security-group-parser
fix/terraform-child-modules
docs/update-architecture
security/restrict-report-output
```

Make focused changes that address one issue or feature.

Before committing, run:

```bash
ruff check .
ruff format .
mypy src
pytest
pre-commit run --all-files
```

All checks must pass before a pull request is submitted.

## Code Standards

Contributions should:

* Use clear and descriptive names
* Include type annotations
* Follow the existing project structure
* Keep functions focused and understandable
* Avoid unnecessary dependencies
* Include concise docstrings where useful
* Handle invalid input explicitly
* Preserve deterministic behaviour
* Avoid hidden network requests or telemetry
* Avoid introducing AI-generated findings into the deterministic analysis layer

ThreatWeaver's security findings must remain reproducible and explainable.

AI or language-model integrations may assist with explanation, but they must not silently create, remove, or modify deterministic findings.

## Testing Requirements

New functionality must include tests.

Bug fixes should include a regression test that fails before the fix and passes afterward.

Tests should cover:

* Expected behaviour
* Invalid input
* Empty input
* Relevant edge cases
* Error handling

Run the complete test suite with:

```bash
pytest
```

## Security Rule Contributions

New security rules should clearly define:

* Rule identifier
* Rule title
* Description
* Supported resource types
* Trigger conditions
* Severity rationale
* Confidence rationale
* Evidence requirements
* Recommended remediation
* Relevant MITRE ATT&CK mappings
* Relevant STRIDE classification, where applicable
* Positive and negative test cases

Rules should avoid generating findings based only on assumptions.

Every finding should be supported by evidence from the analyzed infrastructure.

## Commit Messages

Use concise commit messages written in the imperative mood.

Conventional Commits are recommended:

```text
feat: add Terraform resource extraction
fix: handle missing root module
docs: update graph architecture
test: add malformed plan cases
refactor: simplify resource normalization
security: validate report output path
```

Avoid messages such as:

```text
update
changes
fix stuff
work
final version
```

## Pull Requests

A pull request should:

* Have a clear title
* Explain what changed
* Explain why the change is needed
* Reference the related issue
* Include tests
* Pass all CI checks
* Avoid unrelated changes
* Update documentation when required

Use the following structure in the pull-request description:

```markdown
## Summary

Describe the change.

## Motivation

Explain the problem being solved.

## Changes

- Change one
- Change two

## Testing

Describe the tests performed.

## Related Issue

Closes #123
```

Maintainers may request changes before merging.

## Reporting Bugs

Open a GitHub issue and include:

* A clear description
* Steps to reproduce
* Expected behaviour
* Actual behaviour
* ThreatWeaver version or commit
* Python version
* Operating system
* Relevant logs or sanitized input
* A minimal reproduction, where possible

Do not include credentials, secrets, tokens, private infrastructure details, or other sensitive information.

## Feature Requests

Feature requests should explain:

* The problem
* The proposed behaviour
* The intended users
* Example input and output
* Alternatives considered
* Potential security implications

## Responsible Disclosure

Do not report security vulnerabilities through a public issue.

Follow the instructions in `SECURITY.md`.

## Documentation

Update documentation whenever a change affects:

* Public commands
* Configuration
* Supported resources
* Graph semantics
* Rule behaviour
* Report formats
* Installation
* Architecture

## Licence

By contributing to ThreatWeaver, you agree that your contributions will be licensed under the Apache License 2.0.

## Code of Conduct

All contributors must follow `CODE_OF_CONDUCT.md`.

Thank you for helping build ThreatWeaver.
