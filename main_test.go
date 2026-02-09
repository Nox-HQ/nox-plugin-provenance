package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackSupplyChain)
}

func TestScanWithProvenanceNoMissingAttestation(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "with-provenance"))

	found := findByRule(resp.GetFindings(), "PROV-001")
	if len(found) != 0 {
		t.Errorf("expected no PROV-001 findings when provenance file exists, got %d", len(found))
	}
}

func TestScanWithoutProvenanceFlagsMissingAttestation(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "without-provenance"))

	found := findByRule(resp.GetFindings(), "PROV-001")
	if len(found) == 0 {
		t.Fatal("expected at least one PROV-001 (missing attestation) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("PROV-001 severity should be HIGH, got %v", f.GetSeverity())
		}
	}
}

func TestScanIncompleteProvenanceMetadata(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "incomplete-provenance"))

	found := findByRule(resp.GetFindings(), "PROV-002")
	if len(found) == 0 {
		t.Fatal("expected at least one PROV-002 (incomplete metadata) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("PROV-002 severity should be MEDIUM, got %v", f.GetSeverity())
		}
		reasons := f.GetMetadata()["reasons"]
		if reasons == "" {
			t.Error("PROV-002 finding should include reasons metadata")
		}
	}
}

func TestScanReproducibilityRisk(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "without-provenance"))

	found := findByRule(resp.GetFindings(), "PROV-003")
	if len(found) == 0 {
		t.Fatal("expected at least one PROV-003 (reproducibility risk) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("PROV-003 severity should be MEDIUM, got %v", f.GetSeverity())
		}
		if f.GetLocation() == nil {
			t.Error("PROV-003 finding must include a location")
		}
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

func TestIsProvenanceFile(t *testing.T) {
	tests := []struct {
		name   string
		expect bool
	}{
		{"build.intoto.jsonl", true},
		{"app.intoto.json", true},
		{"provenance.json", true},
		{"attestation.json", true},
		{"release.att.json", true},
		{"package.json", false},
		{"main.go", false},
		{"Makefile", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProvenanceFile(tt.name)
			if got != tt.expect {
				t.Errorf("isProvenanceFile(%q) = %v, want %v", tt.name, got, tt.expect)
			}
		})
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
