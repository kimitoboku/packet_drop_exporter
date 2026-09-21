package symbol

import (
	"crypto/sha256"
	"fmt"
	"os"
)

// Refresher reloads kallsyms when the loaded module set changes. If the
// current resolver is unavailable, it retries on every check so temporary
// permission or mount problems can recover without restarting the exporter.
type Refresher struct {
	resolver      *Resolver
	kallsymsPath  string
	modulesPath   string
	modulesDigest [sha256.Size]byte
	hasDigest     bool
}

func NewRefresher(resolver *Resolver, kallsymsPath, modulesPath string) *Refresher {
	return &Refresher{
		resolver:     resolver,
		kallsymsPath: kallsymsPath,
		modulesPath:  modulesPath,
	}
}

// RefreshIfChanged returns true after publishing a new symbol table.
func (r *Refresher) RefreshIfChanged() (bool, error) {
	digest, digestErr := fileDigest(r.modulesPath)
	changed := digestErr != nil || !r.hasDigest || digest != r.modulesDigest
	if r.resolver != nil && r.resolver.Available() && !changed {
		return false, nil
	}

	loaded, err := Load(r.kallsymsPath)
	if err != nil {
		return false, err
	}
	if r.resolver == nil {
		return false, fmt.Errorf("refresh kallsyms: nil resolver")
	}
	table := loaded.current.Load()
	if table == nil {
		r.resolver.Replace(nil)
	} else {
		r.resolver.Replace(table.entries)
	}
	if digestErr == nil {
		r.modulesDigest = digest
		r.hasDigest = true
	}
	return true, nil
}

func fileDigest(path string) ([sha256.Size]byte, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("read module list %q: %w", path, err)
	}
	return sha256.Sum256(contents), nil
}
