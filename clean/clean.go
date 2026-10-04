// Package clean plans the removal of stale generator-name tags from files that
// aidetect flags but that a person says were not made by generative AI.
//
// It never edits anything it does not understand, and it refuses any file that
// declares its own provenance (C2PA, an AI-ish IPTC DigitalSourceType, IPTC AI
// disclosure fields): removing a file's own claim of origin is not fixing a
// false positive. NewPlan only reads; it cannot modify the file.
package clean

import (
	"fmt"
	"strings"

	"github.com/jbrahy/aidetect"
)

// Edit is one metadata field that can be removed.
type Edit struct {
	Location string // region and field, as in aidetect.Finding.Location
	Detail   string // what matched, e.g. Adobe Firefly: "Adobe Firefly"
}

// Unfixable is a finding that cleaning cannot or should not remove.
type Unfixable struct {
	Finding aidetect.Finding
	Reason  string
}

// Plan lists what cleaning would change in one file.
type Plan struct {
	Path      string
	Format    string
	Remove    []Edit
	Unfixable []Unfixable
}

// ProvenanceError is returned when a file declares its own provenance. The
// findings say where. Nothing is planned or written for such a file.
type ProvenanceError struct {
	Path     string
	Findings []aidetect.Finding
}

func (e *ProvenanceError) Error() string {
	var where []string
	for _, f := range e.Findings {
		where = append(where, f.Location+": "+f.Detail)
	}
	return fmt.Sprintf("%s declares its own provenance, refusing to clean: %s", e.Path, strings.Join(where, "; "))
}

// NewPlan inspects path and returns what could be removed. A file that
// declares provenance yields a *ProvenanceError and a nil Plan.
func NewPlan(path string) (*Plan, error) {
	rep := aidetect.Inspect(path, aidetect.Options{})
	if rep.Verdict == aidetect.VerdictError {
		return nil, fmt.Errorf("%s: %s", path, strings.Join(rep.Errors, "; "))
	}
	var prov []aidetect.Finding
	for _, f := range rep.Findings {
		if f.Provenance {
			prov = append(prov, f)
		}
	}
	if len(prov) > 0 {
		return nil, &ProvenanceError{Path: path, Findings: prov}
	}

	p := &Plan{Path: path, Format: rep.Format}
	at := map[string]int{} // one edit per field, even when several signatures match it
	for _, f := range rep.Findings {
		switch {
		case f.Severity < aidetect.SevWeak:
			// info-level findings do not raise a verdict; leave them alone
		case f.Signature:
			if i, ok := at[f.Location]; ok {
				p.Remove[i].Detail += "; " + f.Detail
				continue
			}
			at[f.Location] = len(p.Remove)
			p.Remove = append(p.Remove, Edit{Location: f.Location, Detail: f.Detail})
		default:
			p.Unfixable = append(p.Unfixable, Unfixable{Finding: f, Reason: "not a single tag naming a tool; cleaning does not remove it"})
		}
	}
	return p, nil
}
