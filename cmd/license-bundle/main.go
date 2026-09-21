// Command license-bundle collects top-level license and notice files for the
// modules linked into packet-drop-exporter. Release archives include the
// generated directory so third-party terms travel with distributed binaries.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *module
}

type listedPackage struct {
	Standard bool
	Module   *module
}

const outputDirectory = "third_party_licenses"

func main() {
	if err := run(outputDirectory); err != nil {
		fmt.Fprintf(os.Stderr, "license-bundle: %v\n", err)
		os.Exit(1)
	}
}

func run(output string) error {
	cleanOutput := filepath.Clean(output)
	if cleanOutput != outputDirectory {
		return fmt.Errorf("output must be %q", outputDirectory)
	}
	output = cleanOutput

	command := exec.Command("go", "list", "-deps", "-json", "./cmd/packet-drop-exporter")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start go list: %w", err)
	}

	modules := make(map[string]module)
	decoder := json.NewDecoder(stdout)
	for {
		var pkg listedPackage
		if err := decoder.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("decode go list output: %w", err)
		}
		if pkg.Standard || pkg.Module == nil || pkg.Module.Main {
			continue
		}
		resolved := *pkg.Module
		if resolved.Replace != nil {
			resolved.Dir = resolved.Replace.Dir
		}
		modules[resolved.Path] = resolved
	}
	if err := command.Wait(); err != nil {
		return fmt.Errorf("go list: %w", err)
	}

	if err := os.RemoveAll(output); err != nil {
		return fmt.Errorf("clear output: %w", err)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return fmt.Errorf("create output: %w", err)
	}

	paths := make([]string, 0, len(modules))
	for path := range modules {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	manifest := new(strings.Builder)
	manifest.WriteString("# Third-Party Licenses\n\n")
	manifest.WriteString("Generated from runtime dependencies of `./cmd/packet-drop-exporter`.\n\n")
	for _, path := range paths {
		mod := modules[path]
		files, err := licenseFiles(mod.Dir)
		if err != nil {
			return fmt.Errorf("find licenses for %s: %w", path, err)
		}
		if len(files) == 0 {
			return fmt.Errorf("module %s has no top-level license or notice file", path)
		}

		directoryName := sanitize(path + "@" + mod.Version)
		destination := filepath.Join(output, directoryName)
		if err := os.MkdirAll(destination, 0o755); err != nil {
			return err
		}
		fmt.Fprintf(manifest, "- `%s %s`\n", path, mod.Version)
		for _, source := range files {
			contents, err := os.ReadFile(source)
			if err != nil {
				return err
			}
			target := filepath.Join(destination, filepath.Base(source))
			if err := os.WriteFile(target, contents, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(manifest, "  - `%s/%s`\n", directoryName, filepath.Base(source))
		}
	}

	if err := os.WriteFile(filepath.Join(output, "README.md"), []byte(manifest.String()), 0o644); err != nil {
		return err
	}
	return nil
}

func licenseFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToUpper(entry.Name())
		if strings.HasPrefix(name, "LICENSE") || strings.HasPrefix(name, "NOTICE") || strings.HasPrefix(name, "COPYING") || strings.HasPrefix(name, "COPYRIGHT") {
			files = append(files, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func sanitize(value string) string {
	replacer := strings.NewReplacer("/", "__", "\\", "__", ":", "_", " ", "_")
	return replacer.Replace(value)
}
