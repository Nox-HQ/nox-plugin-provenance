# nox-plugin-provenance

**SLSA build provenance and attestation verification for software supply chains.**

## Overview

`nox-plugin-provenance` is a Nox security scanner plugin that validates software supply chain integrity by verifying SLSA (Supply-chain Levels for Software Artifacts) attestations and build provenance metadata. It ensures that your build artifacts have proper cryptographic provenance, that attestation metadata is complete, and that build processes are reproducible.

Supply chain attacks have surged in recent years -- from SolarWinds to the xz-utils backdoor. SLSA provenance provides a tamper-proof record of how software was built, what sources were used, and which builder produced the artifact. Without provenance verification, organizations cannot distinguish legitimate builds from compromised ones.

This plugin operates in passive read-only mode. It scans your workspace for in-toto attestation files, build configurations (Makefiles, Dockerfiles, CI configs), and flags missing attestations, incomplete metadata, and non-deterministic build patterns that undermine reproducibility.

## Use Cases

### Enforcing SLSA Compliance in CI/CD Pipelines

Your organization is adopting SLSA Level 2+ and needs to verify that every release has a valid attestation before promotion. The provenance plugin runs in your CI pipeline to block releases that lack proper in-toto attestation files, catching gaps before artifacts reach production.

### Auditing Open-Source Dependencies for Provenance

Your security team reviews third-party libraries and internal packages for supply chain risks. The plugin scans vendored or cloned repositories to verify that provenance files exist and contain complete metadata -- builder ID, materials list, and subject digests -- so auditors can trace every artifact back to its source.

### Detecting Non-Reproducible Builds

Your build pipeline uses `curl | bash` install scripts, unpinned package versions, or `latest` tags in Dockerfiles. These patterns make builds non-deterministic, meaning the same source can produce different binaries. The plugin flags these reproducibility risks in Dockerfiles, Makefiles, CI configs, and build scripts so engineers can pin versions and eliminate drift.

### Meeting FedRAMP and SOC 2 Supply Chain Requirements

Compliance frameworks increasingly require evidence of build provenance and artifact integrity. The plugin generates findings that map directly to control requirements, giving your GRC team machine-readable evidence that build processes follow supply chain security best practices.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-provenance
   ```

2. **Create a test project with a Dockerfile and no provenance**

   ```bash
   mkdir -p demo-provenance && cd demo-provenance

   cat > Dockerfile <<'EOF'
   FROM node:latest
   RUN apt-get install -y curl
   RUN curl -fsSL https://example.com/setup.sh | bash
   COPY . /app
   EOF

   cat > Makefile <<'EOF'
   build:
   	docker build -t myapp:$(DATE) .
   	echo "Built at $(date)"
   EOF
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/provenance demo-provenance/
   ```

4. **Review findings**

   ```
   nox/provenance scan completed: 4 findings

   PROV-001 [HIGH] No SLSA attestation or provenance files found in workspace with build configuration
     Location: demo-provenance/
     Confidence: medium

   PROV-003 [MEDIUM] Build reproducibility risk: Using 'latest' tag is non-deterministic
     Location: demo-provenance/Dockerfile:1
     Confidence: medium

   PROV-003 [MEDIUM] Build reproducibility risk: Package install without version pinning
     Location: demo-provenance/Dockerfile:2
     Confidence: medium

   PROV-003 [MEDIUM] Build reproducibility risk: Piping remote script to shell is non-reproducible
     Location: demo-provenance/Dockerfile:3
     Confidence: medium
   ```

5. **Add a provenance file and re-scan**

   ```bash
   cat > build.intoto.jsonl <<'EOF'
   {"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"myapp","digest":{"sha256":"abc123"}}],"predicate":{"builder":{"id":"https://github.com/actions/runner"},"buildType":"https://github.com/actions/workflow","materials":[{"uri":"git+https://github.com/myorg/myapp","digest":{"sha256":"def456"}}]}}
   EOF

   nox scan --plugin nox/provenance demo-provenance/
   ```

   ```
   nox/provenance scan completed: 3 findings

   PROV-003 [MEDIUM] Build reproducibility risk: Using 'latest' tag is non-deterministic
     Location: demo-provenance/Dockerfile:1
     Confidence: medium

   PROV-003 [MEDIUM] Build reproducibility risk: Package install without version pinning
     Location: demo-provenance/Dockerfile:2
     Confidence: medium

   PROV-003 [MEDIUM] Build reproducibility risk: Piping remote script to shell is non-reproducible
     Location: demo-provenance/Dockerfile:3
     Confidence: medium
   ```

   The PROV-001 finding is gone because a valid attestation file now exists.

## Rules

| Rule ID  | Description | Severity | Confidence | CWE |
|----------|-------------|----------|------------|-----|
| PROV-001 | No SLSA attestation or provenance files found in workspace with build configuration | High | Medium | -- |
| PROV-002 | Incomplete provenance metadata (missing subject, digest, builder ID, materials, or predicate) | Medium | High | -- |
| PROV-003 | Build reproducibility risk: non-deterministic build patterns detected (unpinned versions, `latest` tags, piped remote scripts, embedded dates/random values) | Medium | Medium | -- |

## Supported File Types

### Provenance Files

- `*.intoto.jsonl` / `*.intoto.json`
- `*.provenance.json` / `provenance.json`
- `attestation.json` / `*.att.json`

### Build Configuration Files

- `Makefile`, `Dockerfile`, `Jenkinsfile`, `Taskfile.yml`
- `cloudbuild.yaml` / `cloudbuild.json`
- `.goreleaser.yml` / `.goreleaser.yaml`
- `build.gradle` / `build.gradle.kts` / `pom.xml`

### CI Configuration Files

- `.github/workflows/*.yml` / `.github/workflows/*.yaml`
- `.gitlab-ci.yml`
- `.circleci/config.yml`
- `azure-pipelines.yml`

## Configuration

The plugin operates with sensible defaults and requires no configuration. It scans the entire workspace recursively, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, and `.venv` directories.

Pass `workspace_root` as input to override the default scan directory:

```bash
nox scan --plugin nox/provenance --input workspace_root=/path/to/project
```

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-provenance
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-provenance.git
cd nox-plugin-provenance
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run tests with race detection
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Build Docker image
docker build -t nox-plugin-provenance .
```

## Architecture

The plugin follows the standard Nox plugin architecture, communicating via the Nox Plugin SDK over stdio.

1. **File Discovery**: Recursively walks the workspace, matching files against provenance file patterns (in-toto/SLSA naming conventions), build config files (Makefile, Dockerfile, etc.), and CI config patterns (.github/workflows, .gitlab-ci.yml, etc.).

2. **Provenance Validation**: Parses in-toto attestation files (JSON and JSONL formats), validates the statement structure including subject names and digests, and checks the SLSA predicate for builder ID and materials list.

3. **Reproducibility Analysis**: Scans build configuration files line by line against compiled regex patterns that detect non-deterministic build practices -- piped remote scripts, unpinned package installs, `latest` tags, embedded dates, and random values.

4. **Workspace-Level Assessment**: If build configurations exist but no provenance files are found, emits a high-severity finding for missing attestation.

All analysis is deterministic, offline, and read-only. The plugin never executes build commands or modifies files.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-provenance).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
