package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// provenanceFilePatterns lists filename patterns that indicate SLSA provenance
// or in-toto attestation artifacts.
var provenanceFilePatterns = []string{
	"*.intoto.jsonl",
	"*.intoto.json",
	"*.provenance.json",
	"provenance.json",
	"attestation.json",
	"*.att.json",
}

// buildConfigFiles lists files that describe build processes.
var buildConfigFiles = map[string]bool{
	"Makefile":         true,
	"Dockerfile":       true,
	"Jenkinsfile":      true,
	"Taskfile.yml":     true,
	"cloudbuild.yaml":  true,
	"cloudbuild.json":  true,
	".goreleaser.yml":  true,
	".goreleaser.yaml": true,
	"build.gradle":     true,
	"build.gradle.kts": true,
	"pom.xml":          true,
}

// ciConfigPatterns lists CI configuration file patterns.
var ciConfigPatterns = []string{
	".github/workflows/*.yml",
	".github/workflows/*.yaml",
	".gitlab-ci.yml",
	".circleci/config.yml",
	"azure-pipelines.yml",
}

// nonDeterministicPatterns detects build commands that produce
// non-reproducible outputs.
var nonDeterministicPatterns = []struct {
	Pattern *regexp.Regexp
	Reason  string
}{
	{regexp.MustCompile(`(?i)\bcurl\b.*\|\s*(sh|bash)\b`), "Piping remote script to shell is non-reproducible"},
	{regexp.MustCompile(`(?i)\bwget\b.*\|\s*(sh|bash)\b`), "Piping remote script to shell is non-reproducible"},
	{regexp.MustCompile(`(?i)\b(apt-get|apk|yum)\s+install\s+[a-zA-Z][a-zA-Z0-9._-]*\s*$`), "Package install without version pinning"},
	{regexp.MustCompile(`(?i)\blatest\b`), "Using 'latest' tag is non-deterministic"},
	{regexp.MustCompile(`(?i)\bDATE\b|\bdate\s*\(`), "Embedding build date makes output non-reproducible"},
	{regexp.MustCompile(`(?i)\bRANDOM\b|\brand\(`), "Random values in build produce non-deterministic output"},
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

// inTotoStatement represents a minimal in-toto attestation statement.
type inTotoStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

// slsaPredicate represents a minimal SLSA provenance predicate.
type slsaPredicate struct {
	Builder struct {
		ID string `json:"id"`
	} `json:"builder"`
	BuildType string `json:"buildType"`
	Materials []struct {
		URI    string            `json:"uri"`
		Digest map[string]string `json:"digest"`
	} `json:"materials"`
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/provenance", version).
		Capability("provenance", "SLSA attestation generation and verification").
		Tool("scan", "Scan for missing or incomplete SLSA attestations and provenance metadata", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	hasProvenance := false
	hasBuildConfig := false

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()

		// Check for provenance files.
		if isProvenanceFile(name) {
			hasProvenance = true
			return scanProvenanceFile(resp, path)
		}

		// Check for build configs and scan for reproducibility risks.
		if buildConfigFiles[name] || isCIConfig(path, workspaceRoot) {
			hasBuildConfig = true
			return scanBuildFileForReproducibility(resp, path)
		}

		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	// If there are build configs but no provenance files, flag the missing attestation.
	if hasBuildConfig && !hasProvenance {
		resp.Finding(
			"PROV-001",
			sdk.SeverityHigh,
			sdk.ConfidenceMedium,
			"No SLSA attestation or provenance files found in workspace with build configuration",
		).
			At(workspaceRoot, 0, 0).
			WithMetadata("type", "missing_attestation").
			Done()
	}

	return resp.Build(), nil
}

// isProvenanceFile checks whether a filename matches known provenance naming conventions.
func isProvenanceFile(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range provenanceFilePatterns {
		matched, _ := filepath.Match(pattern, lower)
		if matched {
			return true
		}
	}
	return false
}

// isCIConfig checks whether a path matches CI configuration patterns relative
// to the workspace root.
func isCIConfig(path, workspaceRoot string) bool {
	rel, err := filepath.Rel(workspaceRoot, path)
	if err != nil {
		return false
	}
	for _, pattern := range ciConfigPatterns {
		matched, _ := filepath.Match(pattern, rel)
		if matched {
			return true
		}
	}
	return false
}

// scanProvenanceFile reads and validates an in-toto attestation file.
func scanProvenanceFile(resp *sdk.ResponseBuilder, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var stmt inTotoStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		// Try line-delimited format (JSONL).
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if err := json.Unmarshal([]byte(line), &stmt); err == nil {
				break
			}
		}
	}

	// Check for incomplete metadata.
	incomplete := false
	var reasons []string

	if len(stmt.Subject) == 0 {
		incomplete = true
		reasons = append(reasons, "missing subject")
	} else {
		for _, subj := range stmt.Subject {
			if subj.Name == "" {
				incomplete = true
				reasons = append(reasons, "subject missing name")
			}
			if len(subj.Digest) == 0 {
				incomplete = true
				reasons = append(reasons, "subject missing digest")
			}
		}
	}

	if len(stmt.Predicate) > 0 {
		var pred slsaPredicate
		if err := json.Unmarshal(stmt.Predicate, &pred); err == nil {
			if pred.Builder.ID == "" {
				incomplete = true
				reasons = append(reasons, "missing builder ID")
			}
			if len(pred.Materials) == 0 {
				incomplete = true
				reasons = append(reasons, "missing materials")
			}
		}
	} else {
		incomplete = true
		reasons = append(reasons, "missing predicate")
	}

	if incomplete {
		resp.Finding(
			"PROV-002",
			sdk.SeverityMedium,
			sdk.ConfidenceHigh,
			fmt.Sprintf("Incomplete provenance metadata: %s", strings.Join(reasons, ", ")),
		).
			At(filePath, 0, 0).
			WithMetadata("type", "incomplete_metadata").
			WithMetadata("reasons", strings.Join(reasons, ", ")).
			Done()
	}

	return nil
}

// scanBuildFileForReproducibility checks build configuration files for patterns
// that produce non-deterministic outputs.
func scanBuildFileForReproducibility(resp *sdk.ResponseBuilder, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, nd := range nonDeterministicPatterns {
			if nd.Pattern.MatchString(line) {
				resp.Finding(
					"PROV-003",
					sdk.SeverityMedium,
					sdk.ConfidenceMedium,
					fmt.Sprintf("Build reproducibility risk: %s", nd.Reason),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("type", "reproducibility_risk").
					WithMetadata("reason", nd.Reason).
					Done()
			}
		}
	}

	return scanner.Err()
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-provenance: %v\n", err)
		return 1
	}
	return 0
}
