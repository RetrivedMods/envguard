package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RetrivedMods/envguard/internal/config"
	"github.com/RetrivedMods/envguard/internal/scanner"
)

func TestGitHubToken(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.js"), []byte(`const apiKey = "ghp_123456789012345678901234567890123456";`), 0644)
	if err != nil { t.Fatal(err) }

	result, err := scanner.Scan(dir, config.Default(), false)
	if err != nil { t.Fatal(err) }
	if len(result.Findings) != 1 { t.Fatalf("expected 1 finding, got %d", len(result.Findings)) }
	if result.Findings[0].RuleID != "github-token" { t.Fatalf("unexpected rule: %s", result.Findings[0].RuleID) }
	if result.Findings[0].Match == "ghp_123456789012345678901234567890123456" { t.Fatal("secret was not redacted") }
}

func TestBuildArtifactsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app", "build", "intermediates", "build.ninja")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("A7fK91xQpL2mN8zW5rT0uY3c"), 0644); err != nil { t.Fatal(err) }

	result, err := scanner.Scan(dir, config.Default(), false)
	if err != nil { t.Fatal(err) }
	if len(result.Findings) != 0 { t.Fatalf("expected no findings, got %d", len(result.Findings)) }
}

func TestCleanProject(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}"), 0644); err != nil { t.Fatal(err) }

	result, err := scanner.Scan(dir, config.Default(), false)
	if err != nil { t.Fatal(err) }
	if len(result.Findings) != 0 { t.Fatalf("expected no findings, got %d", len(result.Findings)) }
}
