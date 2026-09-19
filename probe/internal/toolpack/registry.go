package toolpack

import "sort"

// Spec describes one registered tool: its category and parsed params
// schema (design.md Section 8.3 ToolSpec / Appendix A ToolDescriptor).
type Spec struct {
	Name         string
	Category     string // engine | runtime | host
	ParamsSchema map[string]any
}

// Registry is a name -> Spec catalog, generic over any PlatformAdapter.
type Registry struct {
	specs map[string]Spec
}

func NewRegistry() *Registry {
	return &Registry{specs: make(map[string]Spec)}
}

func (r *Registry) Register(spec Spec) {
	r.specs[spec.Name] = spec
}

func (r *Registry) Get(name string) (Spec, bool) {
	s, ok := r.specs[name]
	return s, ok
}

// List returns all registered specs sorted by name (deterministic
// manifest ordering).
func (r *Registry) List() []Spec {
	names := make([]string, 0, len(r.specs))
	for n := range r.specs {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Spec, 0, len(names))
	for _, n := range names {
		out = append(out, r.specs[n])
	}
	return out
}
