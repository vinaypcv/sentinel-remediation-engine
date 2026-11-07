package workflow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"twitch-security/domain"
)

type GeneratedPatch struct {
	RelativePath string
	Content      []byte
	Summary      string
}

type PatchGenerator interface {
	Generate(context.Context, domain.Vulnerability) (GeneratedPatch, error)
}

type GoModPatchGenerator struct {
	WorkspaceRoot string
}

func (g GoModPatchGenerator) Generate(ctx context.Context, vuln domain.Vulnerability) (GeneratedPatch, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedPatch{}, err
	}
	if vuln.Dependency == "" || vuln.FixedVersion == "" {
		return GeneratedPatch{}, fmt.Errorf("remediation metadata required: dependency and fixed_version must be set")
	}
	if err := module.CheckPath(vuln.Dependency); err != nil {
		return GeneratedPatch{}, fmt.Errorf("invalid dependency module path: %w", err)
	}
	if !semver.IsValid(vuln.FixedVersion) || semver.Canonical(vuln.FixedVersion) != vuln.FixedVersion {
		return GeneratedPatch{}, fmt.Errorf("fixed_version must be a canonical Go module semantic version")
	}

	root := g.WorkspaceRoot
	if root == "" {
		root = "."
	}
	goModPath := filepath.Join(root, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return GeneratedPatch{}, fmt.Errorf("read go.mod: %w", err)
	}
	file, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return GeneratedPatch{}, fmt.Errorf("parse go.mod: %w", err)
	}

	currentVersion := ""
	for _, requirement := range file.Require {
		if requirement.Mod.Path == vuln.Dependency {
			currentVersion = requirement.Mod.Version
			break
		}
	}
	if currentVersion == "" {
		return GeneratedPatch{}, fmt.Errorf("dependency %q is not an existing go.mod requirement", vuln.Dependency)
	}
	if !semver.IsValid(currentVersion) || semver.Compare(vuln.FixedVersion, currentVersion) <= 0 {
		return GeneratedPatch{}, fmt.Errorf("fixed version %s must be greater than current version %s", vuln.FixedVersion, currentVersion)
	}
	for _, replacement := range file.Replace {
		if replacement.Old.Path == vuln.Dependency {
			return GeneratedPatch{}, fmt.Errorf("dependency %q uses a replace directive; automatic upgrade is not supported", vuln.Dependency)
		}
	}

	file.AddRequire(vuln.Dependency, vuln.FixedVersion)
	updated, err := file.Format()
	if err != nil {
		return GeneratedPatch{}, fmt.Errorf("format updated go.mod: %w", err)
	}
	return GeneratedPatch{
		RelativePath: "go.mod",
		Content:      updated,
		Summary:      fmt.Sprintf("upgrade %s from %s to %s", vuln.Dependency, currentVersion, vuln.FixedVersion),
	}, nil
}
