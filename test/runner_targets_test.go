package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberspacesec/gxx/pkg/runner"
	"github.com/cyberspacesec/gxx/types"

	"github.com/projectdiscovery/goflags"
)

func TestLoadTargetsFromArgs(t *testing.T) {
	opts := &types.CmdOptions{
		Target: goflags.StringSlice{"https://example.com", "https://example.com", "https://www.baidu.com"},
	}

	targets := runner.LoadTargets(opts)
	if len(targets) != 2 {
		t.Fatalf("expected 2 unique targets, got %d (%v)", len(targets), targets)
	}
}

func TestLoadTargetsFromFile(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetFile, []byte("example.com\nexample.com\nwww.baidu.com\n"), 0o600); err != nil {
		t.Fatalf("failed to write temp targets file: %v", err)
	}

	opts := &types.CmdOptions{
		TargetsFile: targetFile,
	}

	targets := runner.LoadTargets(opts)
	if len(targets) != 2 {
		t.Fatalf("expected 2 unique targets from file, got %d (%v)", len(targets), targets)
	}
}
