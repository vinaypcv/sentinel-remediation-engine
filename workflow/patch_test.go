package workflow

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"twitch-security/controller"
	"twitch-security/domain"
)

func TestGoModPatchGeneratorUpgradesExistingDependency(t *testing.T) {
	root := t.TempDir()
	goMod := "module example.test/service\n\ngo 1.26.0\n\nrequire example.com/library v1.2.3\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}

	patch, err := (GoModPatchGenerator{WorkspaceRoot: root}).Generate(context.Background(), domain.Vulnerability{
		Dependency:   "example.com/library",
		FixedVersion: "v1.3.0",
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if patch.RelativePath != "go.mod" || !strings.Contains(string(patch.Content), "example.com/library v1.3.0") {
		t.Fatalf("generated patch does not contain expected dependency update: %+v", patch)
	}
	current, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != goMod {
		t.Fatal("patch generation modified the source workspace")
	}
}

func TestGoModPatchGeneratorRejectsDowngradeAndUnknownDependency(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/service\n\ngo 1.26.0\n\nrequire example.com/library v1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	generator := GoModPatchGenerator{WorkspaceRoot: root}
	for _, vuln := range []domain.Vulnerability{
		{Dependency: "example.com/library", FixedVersion: "v1.2.2"},
		{Dependency: "example.com/unknown", FixedVersion: "v1.3.0"},
	} {
		if _, err := generator.Generate(context.Background(), vuln); err == nil {
			t.Errorf("Generate(%+v) succeeded; expected validation failure", vuln)
		}
	}
}

type staticPatchGenerator struct {
	patch GeneratedPatch
	err   error
}

func (g staticPatchGenerator) Generate(context.Context, domain.Vulnerability) (GeneratedPatch, error) {
	return g.patch, g.err
}

type recordingPatchVerifier struct {
	err      error
	verified bool
}

func (v *recordingPatchVerifier) Verify(context.Context, GeneratedPatch) error {
	v.verified = true
	return v.err
}

func TestExecuteGeneratedRemediationVerifiesPatchAndRollsBackOnFailure(t *testing.T) {
	engine := NewRemediationEngine(controller.NewVerificationController())
	patch := GeneratedPatch{RelativePath: "go.mod", Content: []byte("module example.test/service\n"), Summary: "upgrade dependency"}
	verifier := &recordingPatchVerifier{}
	state, err := engine.ExecuteGeneratedRemediation(context.Background(), domain.Vulnerability{ID: "success"}, staticPatchGenerator{patch: patch}, verifier)
	if err != nil || state.CurrentPhase != "COMPLETED" || !verifier.verified {
		t.Fatalf("successful verification did not complete: state=%+v err=%v verified=%v", state, err, verifier.verified)
	}

	verifier = &recordingPatchVerifier{err: os.ErrPermission}
	state, err = engine.ExecuteGeneratedRemediation(context.Background(), domain.Vulnerability{ID: "failure"}, staticPatchGenerator{patch: patch}, verifier)
	if err == nil || state.CurrentPhase != "ROLLED_BACK" {
		t.Fatalf("verification failure was not rolled back: state=%+v err=%v", state, err)
	}
}

func TestDockerVerifierRejectsNonGoModPatchWithoutLaunchingContainer(t *testing.T) {
	verifier := DockerSandboxVerifier{DockerPath: "docker-executable-that-must-not-run"}
	err := verifier.Verify(context.Background(), GeneratedPatch{RelativePath: "../outside", Content: []byte("unsafe")})
	if err == nil || !strings.Contains(err.Error(), "only accepts generated go.mod updates") {
		t.Fatalf("Verify() error = %v, want invalid-path rejection", err)
	}
}

func TestSandboxDockerArgsUsePersistentCacheAndIsolatedWorkspace(t *testing.T) {
	args := sandboxDockerArgs("C:/workspace", "C:/go/pkg/mod", "golang:1.26", "sentinel-test-container", false)
	joined := strings.Join(args, " ")
	for _, expected := range []string{
		"type=volume,source=" + sandboxBuildCacheVolume + ",target=/tmp",
		"type=bind,source=C:/workspace,target=/workspace,readonly",
		"type=bind,source=C:/go/pkg/mod,target=/go/pkg/mod,readonly",
		"/sandbox:rw,exec,nosuid,nodev,size=1g,mode=1777",
		"GOCACHE=/tmp/gocache",
		"GOPROXY=off",
		"go test -v -mod=mod ./...",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("sandbox Docker args do not contain %q: %s", expected, joined)
		}
	}
	if strings.Contains(joined, "--network=bridge") {
		t.Fatal("sandbox unexpectedly enables container networking")
	}
}

func TestSandboxDockerArgsEnableGoBuildTracing(t *testing.T) {
	args := sandboxDockerArgs("workspace", "module-cache", "golang:1.26", "sentinel-test-container", true)
	if !strings.Contains(strings.Join(args, " "), "go test -x -v -mod=mod ./...") {
		t.Fatalf("debug sandbox args do not enable Go build tracing: %v", args)
	}
}

func TestSandboxOutputTailKeepsOnlyMostRecentBytes(t *testing.T) {
	tail := &sandboxOutputTail{limit: 8}
	if _, err := tail.Write([]byte("first ")); err != nil {
		t.Fatal(err)
	}
	if _, err := tail.Write([]byte("last output")); err != nil {
		t.Fatal(err)
	}
	if got := tail.suffix(); !strings.HasSuffix(got, "output") || strings.Contains(got, "first") {
		t.Fatalf("suffix() = %q, want only the last 8 bytes", got)
	}
}

func TestModuleCacheFromEnvironmentUsesGoCacheOverrides(t *testing.T) {
	expectedCache := filepath.Join(t.TempDir(), "modules")
	customCache, err := moduleCacheFromEnvironment(expectedCache, "C:/custom/gopath")
	if err != nil || customCache != expectedCache {
		t.Fatalf("module cache override = %q, err=%v", customCache, err)
	}
	goPath, err := moduleCacheFromEnvironment("", filepath.Join("first", "gopath")+string(os.PathListSeparator)+"second")
	if err != nil || goPath != filepath.Join("first", "gopath", "pkg", "mod") {
		t.Fatalf("GOPATH module cache = %q, err=%v", goPath, err)
	}
}

func TestSandboxWorkspaceCopyExcludesCredentials(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":     "module example.test/service\n",
		".env":       "TOKEN=not-for-sandbox\n",
		"service.go": "package service\n",
	} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyWorkspace(source, destination); err != nil {
		t.Fatalf("copyWorkspace() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, ".env")); !os.IsNotExist(err) {
		t.Fatalf("credential file was copied into sandbox: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, "service.go")); err != nil {
		t.Fatalf("source file was not copied into sandbox: %v", err)
	}
	patchedGoMod := []byte("module example.test/service\n\ngo 1.26.0\n")
	if err := os.WriteFile(filepath.Join(destination, "go.mod"), patchedGoMod, 0o600); err != nil {
		t.Fatalf("sandbox copy should allow patch staging: %v", err)
	}
}
