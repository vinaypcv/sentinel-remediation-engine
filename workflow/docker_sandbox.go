package workflow

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"twitch-security/storage"
)

const (
	defaultSandboxTimeout   = 30 * time.Minute
	sandboxBuildCacheVolume = "sentinel-remediation-go-build-cache"
	sandboxOutputTailLimit  = 16 * 1024
)

type PatchVerifier interface {
	Verify(context.Context, GeneratedPatch) error
}

type DockerSandboxVerifier struct {
	WorkspaceRoot string
	Image         string
	DockerPath    string
	Timeout       time.Duration
	Debug         bool
}

func (v DockerSandboxVerifier) Verify(ctx context.Context, patch GeneratedPatch) error {
	if patch.RelativePath != "go.mod" {
		return fmt.Errorf("sandbox only accepts generated go.mod updates")
	}
	worktree, moduleCache, err := prepareSandboxWorkspace(ctx, v.WorkspaceRoot, patch)
	if err != nil {
		return err
	}
	defer os.RemoveAll(worktree)

	image := v.Image
	if image == "" {
		image = "golang:1.26"
	}
	dockerPath := v.DockerPath
	if dockerPath == "" {
		dockerPath = "docker"
	}
	containerName := "sentinel-remediation-" + strings.TrimPrefix(filepath.Base(worktree), "sentinel-remediation-sandbox-")
	args := sandboxDockerArgs(worktree, moduleCache, image, containerName, v.Debug)
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = defaultSandboxTimeout
	}
	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(verifyCtx, dockerPath, args...)
	outputTail := &sandboxOutputTail{limit: sandboxOutputTailLimit}
	command.Stdout = io.MultiWriter(os.Stdout, outputTail)
	command.Stderr = io.MultiWriter(os.Stderr, outputTail)
	fmt.Fprintf(os.Stderr, "sandbox: running isolated Go tests (image=%s timeout=%s cache-volume=%s debug=%t)\n", image, timeout, sandboxBuildCacheVolume, v.Debug)
	verificationStarted := time.Now()
	err = command.Run()
	verificationDuration := time.Since(verificationStarted)
	storage.GlobalMetrics.RecordSandboxStage("docker_verify", verificationDuration)
	fmt.Fprintf(os.Stderr, "sandbox: Docker verification completed in %s\n", verificationDuration)
	if err != nil {
		if verifyCtx.Err() != nil {
			stopSandboxContainer(dockerPath, containerName)
			return fmt.Errorf("isolated go test stopped after %s (%v): %w%s", timeout, verifyCtx.Err(), err, outputTail.suffix())
		}
		return fmt.Errorf("isolated go test failed: %w%s", err, outputTail.suffix())
	}
	return nil
}

func prepareSandboxWorkspace(ctx context.Context, workspaceRoot string, patch GeneratedPatch) (worktree, moduleCache string, err error) {
	started := time.Now()
	defer func() {
		duration := time.Since(started)
		storage.GlobalMetrics.RecordSandboxStage("workspace_prepare", duration)
		fmt.Fprintf(os.Stderr, "sandbox: workspace preparation completed in %s\n", duration)
		if err != nil && worktree != "" {
			_ = os.RemoveAll(worktree)
		}
	}()

	root := workspaceRoot
	if root == "" {
		root = "."
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	moduleCache, err = goModuleCache(ctx)
	if err != nil {
		return "", "", err
	}
	worktree, err = os.MkdirTemp("", "sentinel-remediation-sandbox-*")
	if err != nil {
		return "", "", err
	}
	if err = copyWorkspace(root, worktree); err != nil {
		return worktree, "", fmt.Errorf("prepare sandbox workspace: %w", err)
	}
	if err = os.WriteFile(filepath.Join(worktree, patch.RelativePath), patch.Content, 0o444); err != nil {
		return worktree, "", fmt.Errorf("stage generated patch in sandbox: %w", err)
	}
	return worktree, moduleCache, nil
}

func sandboxDockerArgs(worktree, moduleCache, image, containerName string, debug bool) []string {
	goTestArgs := "go test -v -mod=mod ./..."
	if debug {
		goTestArgs = "go test -x -v -mod=mod ./..."
	}
	return []string{
		"run", "--rm", "--pull=never", "--network=none", "--read-only",
		"--name", containerName,
		"--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256",
		"--memory=2g", "--cpus=2", "--user=65532:65532",
		"--mount", "type=volume,source=" + sandboxBuildCacheVolume + ",target=/tmp",
		"--tmpfs", "/sandbox:rw,exec,nosuid,nodev,size=1g,mode=1777",
		"--mount", "type=bind,source=" + worktree + ",target=/workspace,readonly",
		"--mount", "type=bind,source=" + moduleCache + ",target=/go/pkg/mod,readonly",
		"--workdir", "/workspace",
		"--env", "GOCACHE=/tmp/gocache",
		"--env", "GOTMPDIR=/sandbox/tmp",
		"--env", "TMPDIR=/sandbox/tmp",
		"--env", "GOTOOLCHAIN=local",
		"--env", "GOPROXY=off",
		"--env", "GOSUMDB=off",
		image, "sh", "-c", "set -eu; mkdir -p /sandbox/tmp /tmp/gocache; cp -R /workspace /sandbox/candidate; chmod -R u+rwX /sandbox/candidate; cd /sandbox/candidate; " + goTestArgs,
	}
}

func stopSandboxContainer(dockerPath, containerName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, dockerPath, "stop", "--time=1", containerName).Run()
}

type sandboxOutputTail struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func (t *sandboxOutputTail) Write(data []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = append(t.data, data...)
	if len(t.data) > t.limit {
		t.data = append([]byte(nil), t.data[len(t.data)-t.limit:]...)
	}
	return len(data), nil
}

func (t *sandboxOutputTail) suffix() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(bytes.TrimSpace(t.data)) == 0 {
		return " (no Docker/Go output captured; use --sandbox-debug to show Go build commands)"
	}
	return "\nlast sandbox output:\n" + string(t.data)
}

func goModuleCache(ctx context.Context) (string, error) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		return moduleCacheFromEnvironment(os.Getenv("GOMODCACHE"), os.Getenv("GOPATH"))
	}
	output, err := exec.CommandContext(ctx, goPath, "env", "GOMODCACHE").Output()
	if err != nil {
		return "", fmt.Errorf("locate Go module cache: %w", err)
	}
	path := strings.TrimSpace(string(output))
	if path == "" {
		return "", fmt.Errorf("Go module cache path is empty")
	}
	return filepath.Clean(path), nil
}

func moduleCacheFromEnvironment(moduleCache, goPath string) (string, error) {
	if moduleCache != "" {
		return filepath.Clean(moduleCache), nil
	}
	for _, path := range filepath.SplitList(goPath) {
		if path != "" {
			return filepath.Join(path, "pkg", "mod"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve default Go module cache without go on PATH: %w", err)
	}
	return filepath.Join(home, "go", "pkg", "mod"), nil
}

func copyWorkspace(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		first := strings.ToLower(strings.Split(filepath.ToSlash(relative), "/")[0])
		if first == ".git" || first == ".gocache" || first == ".gotmp" || first == ".aws" || first == ".ssh" || first == "secrets" || first == "node_modules" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are not allowed in sandbox input: %s", relative)
		}
		if !entry.IsDir() {
			if !entry.Type().IsRegular() {
				return fmt.Errorf("unsupported file type in sandbox input: %s", relative)
			}
			name := strings.ToLower(entry.Name())
			if name == ".env" || strings.HasPrefix(name, ".env.") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".pfx") || strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cer") || strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".log") {
				return nil
			}
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
