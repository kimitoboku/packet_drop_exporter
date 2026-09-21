package symbol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRefresherReloadsAfterModuleListChange(t *testing.T) {
	directory := t.TempDir()
	kallsymsPath := filepath.Join(directory, "kallsyms")
	modulesPath := filepath.Join(directory, "modules")
	writeTestFile(t, kallsymsPath, "0000000000001000 T first\n")
	writeTestFile(t, modulesPath, "first 1 0 - Live 0x0\n")

	resolver, err := Load(kallsymsPath)
	if err != nil {
		t.Fatal(err)
	}
	refresher := NewRefresher(resolver, kallsymsPath, modulesPath)
	if refreshed, err := refresher.RefreshIfChanged(); err != nil || !refreshed {
		t.Fatalf("initial refresh = %v, %v", refreshed, err)
	}
	if refreshed, err := refresher.RefreshIfChanged(); err != nil || refreshed {
		t.Fatalf("unchanged refresh = %v, %v", refreshed, err)
	}

	writeTestFile(t, kallsymsPath, "0000000000002000 T second\n")
	writeTestFile(t, modulesPath, "second 1 0 - Live 0x0\n")
	if refreshed, err := refresher.RefreshIfChanged(); err != nil || !refreshed {
		t.Fatalf("changed refresh = %v, %v", refreshed, err)
	}
	if got := resolver.Resolve(0x2000); got != "second" {
		t.Fatalf("resolved symbol after refresh = %q", got)
	}
}

func TestRefresherRetriesUnavailableResolver(t *testing.T) {
	directory := t.TempDir()
	kallsymsPath := filepath.Join(directory, "kallsyms")
	modulesPath := filepath.Join(directory, "modules")
	writeTestFile(t, kallsymsPath, "0000000000000000 T hidden\n")
	writeTestFile(t, modulesPath, "stable\n")

	resolver, err := Load(kallsymsPath)
	if err != nil {
		t.Fatal(err)
	}
	refresher := NewRefresher(resolver, kallsymsPath, modulesPath)
	writeTestFile(t, kallsymsPath, "0000000000003000 T recovered\n")
	if refreshed, err := refresher.RefreshIfChanged(); err != nil || !refreshed {
		t.Fatalf("recovery refresh = %v, %v", refreshed, err)
	}
	if got := resolver.Resolve(0x3000); got != "recovered" {
		t.Fatalf("resolved symbol after recovery = %q", got)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
