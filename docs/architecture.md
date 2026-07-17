# ThreatWeaver Architecture

## Overview

ThreatWeaver converts Infrastructure-as-Code into a normalized security graph and uses deterministic analysis to discover evidence-backed attack paths.

## Processing Pipeline

```text
Infrastructure-as-Code
        ↓
Parser
        ↓
Normalized Resource Model
        ↓
Security Graph
        ↓
Rule Engine
        ↓
Attack-Path Search
        ↓
Risk and Confidence Scoring
        ↓
Reports and Visualizations
