package symbol

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

type Entry struct {
	Address uint64
	Name    string
}

type symbolTable struct {
	entries []Entry
}

// Resolver performs nearest-symbol lookup while keeping raw addresses out of
// metrics and logs. Replacements are atomic so module refreshes never expose a
// partially parsed table to collection.
type Resolver struct {
	current atomic.Pointer[symbolTable]
}

func Load(path string) (*Resolver, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open kallsyms %q: %w", path, err)
	}
	defer file.Close()

	entries, err := Parse(file)
	if err != nil {
		return nil, fmt.Errorf("parse kallsyms %q: %w", path, err)
	}
	return New(entries), nil
}

func New(entries []Entry) *Resolver {
	resolver := &Resolver{}
	resolver.Replace(entries)
	return resolver
}

// Replace publishes a complete symbol table in one atomic operation.
func (r *Resolver) Replace(entries []Entry) {
	if r == nil {
		return
	}
	copyEntries := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Address != 0 && entry.Name != "" {
			copyEntries = append(copyEntries, entry)
		}
	}
	sort.Slice(copyEntries, func(i, j int) bool {
		return copyEntries[i].Address < copyEntries[j].Address
	})
	r.current.Store(&symbolTable{entries: copyEntries})
}

func Parse(reader io.Reader) ([]Entry, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	entries := make([]Entry, 0)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		address, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || address == 0 || fields[2] == "" {
			continue
		}
		entries = append(entries, Entry{Address: address, Name: fields[2]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (r *Resolver) Available() bool {
	if r == nil {
		return false
	}
	table := r.current.Load()
	return table != nil && len(table.entries) > 0
}

func (r *Resolver) Resolve(address uint64) string {
	if r == nil || address == 0 {
		return "unknown"
	}
	table := r.current.Load()
	if table == nil || len(table.entries) == 0 {
		return "unknown"
	}
	index := sort.Search(len(table.entries), func(index int) bool {
		return table.entries[index].Address > address
	})
	if index == 0 {
		return "unknown"
	}
	return table.entries[index-1].Name
}
