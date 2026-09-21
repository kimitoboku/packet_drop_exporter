package symbol

import (
	"strings"
	"testing"
)

func TestParseAndNearestSymbol(t *testing.T) {
	entries, err := Parse(strings.NewReader(`
0000000000001000 T first
0000000000002000 t second [module]
0000000000000000 T hidden
bad-address T ignored
`))
	if err != nil {
		t.Fatal(err)
	}
	resolver := New(entries)
	if !resolver.Available() {
		t.Fatal("resolver should be available")
	}
	cases := []struct {
		address uint64
		want    string
	}{
		{0x0fff, "unknown"},
		{0x1000, "first"},
		{0x1fff, "first"},
		{0x2000, "second"},
		{0x2fff, "second"},
	}
	for _, test := range cases {
		if got := resolver.Resolve(test.address); got != test.want {
			t.Errorf("Resolve(0x%x) = %q, want %q", test.address, got, test.want)
		}
	}
}

func TestZeroKallsymsIsUnavailable(t *testing.T) {
	resolver := New([]Entry{{Address: 0, Name: "zero"}})
	if resolver.Available() {
		t.Fatal("zero address must not make resolver available")
	}
	if got := resolver.Resolve(0x1000); got != "unknown" {
		t.Fatalf("Resolve with unavailable resolver = %q", got)
	}
}
