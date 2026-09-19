package registry

import "testing"

// TestTokenEqual exercises the constant-time bootstrap-token comparison
// (design.md Section 8.4a v1.5, review.md S1) directly: correctness must
// hold regardless of the constant-time mechanics underneath.
func TestTokenEqual(t *testing.T) {
	cases := []struct {
		name              string
		stored, presented string
		want              bool
	}{
		{"exact match", "tok-1", "tok-1", true},
		{"mismatch same length", "tok-1", "tok-2", false},
		{"mismatch different length", "tok-1", "tok-12345", false},
		{"both empty", "", "", true},
		{"stored empty presented not", "", "tok-1", false},
		{"stored not presented empty", "tok-1", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tokenEqual(c.stored, c.presented); got != c.want {
				t.Fatalf("tokenEqual(%q, %q) = %v, want %v", c.stored, c.presented, got, c.want)
			}
		})
	}
}
