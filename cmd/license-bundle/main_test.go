package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRunRejectsUnsafeOutput(t *testing.T) {
	for _, output := range []string{"", ".", "..", "../licenses", filepath.Join(string(filepath.Separator), "tmp", "licenses")} {
		t.Run(output, func(t *testing.T) {
			if err := run(output); err == nil {
				t.Fatalf("run(%q) succeeded, want an unsafe-output error", output)
			}
		})
	}
}

func TestLicenseFiles(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"LICENSE", "NOTICE.txt", "README.md"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(directory, "LICENSES"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := licenseFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(directory, "LICENSE"), filepath.Join(directory, "NOTICE.txt")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("licenseFiles() = %v, want %v", got, want)
	}
}

func TestSanitize(t *testing.T) {
	if got, want := sanitize("example.com/a:b v1.0.0"), "example.com__a_b_v1.0.0"; got != want {
		t.Fatalf("sanitize() = %q, want %q", got, want)
	}
}
