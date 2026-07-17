# Security Policy

## Overview

ThreatWeaver is a cybersecurity analysis project. Protecting users, contributors, and the integrity of its findings is a core priority.

This document explains how to report vulnerabilities affecting ThreatWeaver.

## Supported Versions

ThreatWeaver is currently under active early development.

Security fixes will normally be applied to the latest version of the `main` branch and the latest published release.

| Version          | Supported   |
| ---------------- | ----------- |
| Latest release   | Yes         |
| `main` branch    | Yes         |
| Older releases   | Best effort |
| Unofficial forks | No          |

This policy may change after the project reaches a stable release.

## Reporting a Vulnerability

Please do not disclose security vulnerabilities through:

* Public GitHub issues
* Public GitHub discussions
* Pull-request comments
* Social media
* Other public channels

Use GitHub's private vulnerability reporting feature when it is enabled for the repository:

1. Open the ThreatWeaver repository.
2. Select **Security**.
3. Select **Advisories**.
4. Select **Report a vulnerability**.
5. Provide the requested details.

If private vulnerability reporting is not available, contact the project maintainer privately.

**Project maintainer:** Anirudh N Shandilya

Do not send proof-of-concept material containing real credentials, private infrastructure data, personal information, or data obtained without authorization.

## What to Include

A useful report should contain:

* A clear description of the vulnerability
* The affected version or commit
* The affected component
* Steps to reproduce
* A minimal proof of concept
* The expected security impact
* Preconditions required for exploitation
* Suggested remediation, when available
* Whether the issue is already public
* Your preferred name for acknowledgement

Reports should use test data and infrastructure that you own or have explicit authorization to assess.

## Vulnerabilities of Interest

Examples include:

* Arbitrary code execution
* Command injection
* Path traversal
* Unsafe file handling
* Insecure deserialization
* Dependency vulnerabilities with a demonstrated impact
* Exposure of credentials or sensitive infrastructure information
* Unauthorized network requests
* Server-side request forgery
* Report-generation injection
* Malicious Terraform plan handling
* Denial-of-service conditions
* Incorrect trust-boundary enforcement
* Security findings that can be silently manipulated or suppressed
* Unsafe plugin or extension behaviour
* CI/CD workflow vulnerabilities
* Supply-chain risks affecting distributed releases

## Usually Out of Scope

The following are generally not considered project vulnerabilities unless they create a demonstrated security impact:

* Missing security findings
* False positives
* Feature requests
* Documentation errors
* Vulnerabilities in unsupported versions
* Issues requiring a deliberately modified local installation
* Social-engineering attacks against maintainers
* Vulnerabilities that exist only in an unofficial fork
* Automated dependency reports without evidence of exploitability
* Attacks requiring access that already provides equivalent control

Incorrect findings and parser weaknesses are still valuable bug reports, but they can usually be submitted through the normal issue tracker when they do not expose sensitive information or create an exploitable vulnerability.

## Disclosure Process

After receiving a report, maintainers will aim to:

1. Acknowledge the report.
2. Reproduce and assess the issue.
3. Determine its severity and affected versions.
4. Develop and test a fix.
5. Coordinate a release and disclosure.
6. Credit the reporter when requested.

Complex vulnerabilities may require additional investigation.

Please allow maintainers a reasonable opportunity to investigate and resolve the issue before public disclosure.

## Coordinated Disclosure

Reporters are asked to:

* Avoid public disclosure before a fix is available
* Avoid accessing data that is not necessary to demonstrate the issue
* Avoid privacy violations, data destruction, and service disruption
* Test only systems they own or are authorized to assess
* Provide maintainers with sufficient information to reproduce the issue
* Act in good faith

## Security Design Principles

ThreatWeaver aims to follow these principles:

* Local-first execution
* Deterministic security analysis
* Evidence-backed findings
* Transparent scoring
* Minimal network access
* Safe handling of untrusted input
* No hidden telemetry
* Least-privilege integrations
* Explicit configuration
* Secure defaults

## Sensitive Data

Terraform plans and infrastructure files may contain sensitive information.

Users should:

* Review files before sharing them
* Remove credentials and secrets
* Avoid committing plan files containing sensitive values
* Restrict access to generated reports
* Use sanitized examples when opening issues
* Store reports according to their organization's security policies

ThreatWeaver should never be treated as a secret-management system.

## Dependency Security

Potential dependency vulnerabilities should include:

* The affected package and version
* The relevant advisory
* Evidence that ThreatWeaver uses the vulnerable functionality
* The practical impact on ThreatWeaver users

Automated dependency alerts are useful, but exploitability and project impact should be assessed before assigning severity.

## Safe Harbour

Security research conducted in good faith and in accordance with this policy will be considered authorized with respect to the ThreatWeaver project itself.

This safe-harbour statement does not authorize testing against third-party systems, services, infrastructure, or users.

Researchers must comply with applicable laws and obtain permission before testing systems they do not own.

Thank you for helping keep ThreatWeaver and its users secure.
