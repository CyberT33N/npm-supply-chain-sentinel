# Solution Overview

`npm-supply-chain-sentinel` is a cross-platform Node.js scanner and threat-intelligence repository for detecting documented npm supply-chain compromises, malicious install hooks, persistence artifacts, and campaign IOCs across individual projects or entire hosts.

## Core Capabilities

- curated IOC and campaign dataset
- cross-platform filesystem and package scanning
- PNPM 11 Fortress governance auditing for managed project roots
- standalone PNPM governance CLI execution for explicit project roots
- project-mode and machine-wide scan modes
- worker-thread-based parallel traversal
- `ripgrep`-backed content inspection
- blocklist generation and optional remediation flows

## Bounded Context

From a Domain-Driven Design perspective, the bounded context is **Supply-Chain Threat Detection and Response**.

That means:

- the domain core is the detection and governance policy model,
- the CLI is an orchestration and delivery adapter,
- generated blocklists and incident reports are read models,
- governance auditing and IOC scanning are related but intentionally distinct surfaces,
- the PNPM governance surface can be executed on its own without invoking the broader threat-hunting flow.

## Runtime Model

From a 12-Factor perspective, the scanner is modeled as a stateless CLI process:

- configuration is explicit through CLI arguments,
- runtime dependencies are pinned and documented,
- generated operational reports are written to explicit runtime paths under `generated/`,
- administrative mutation is isolated to explicit remediation commands.
