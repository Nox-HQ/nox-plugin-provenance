# nox-plugin-provenance

SLSA provenance and attestation verification plugin for the [Nox](https://github.com/nox-hq/nox) security scanner.

## Description

`nox-plugin-provenance` scans workspace directories for SLSA attestation and provenance artifacts. It detects missing attestations, incomplete provenance metadata, and build reproducibility risks by analyzing in-toto attestation files and build configuration.

## Track

**Supply Chain & Provenance** -- artifact-centric supply chain audit. Read-only, passive risk class.

## Rules

| Rule ID  | Description             | Severity | Detection Method                         |
|----------|-------------------------|----------|------------------------------------------|
| PROV-001 | Missing Attestation     | HIGH     | No .intoto.jsonl or provenance files found |
| PROV-002 | Incomplete Metadata     | MEDIUM   | Missing builder, materials, or subject fields |
| PROV-003 | Reproducibility Risk    | MEDIUM   | Non-deterministic build steps detected   |

## Installation

```bash
nox plugin install nox-hq/nox-plugin-provenance
```

## Usage

```bash
# Run via Nox
nox scan --plugin nox/provenance .

# Run standalone
nox-plugin-provenance
```

## Development

```bash
# Build
make build

# Run tests
make test

# Lint
make lint

# Clean build artifacts
make clean
```

## License

Apache-2.0
