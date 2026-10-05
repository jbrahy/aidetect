package clean

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Attestation is the caller's assertion that the file was not made by
// generative AI. It cannot be verified; it is required so that every rewrite is
// a recorded, deliberate claim, and it is copied into the Result.
type Attestation struct {
	HumanMade bool   `json:"human_made"`
	Note      string `json:"note,omitempty"`
}

// ErrNotAttested is returned when Apply is called without HumanMade set.
var ErrNotAttested = errors.New("clean: refusing to rewrite a file without an attestation that it is not AI-generated")

// UnsupportedError is returned when a field the plan wants to remove sits in a
// place this package cannot rewrite safely. Nothing is written.
type UnsupportedError struct {
	Path      string
	Format    string
	Locations []string
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("%s: cannot remove %s from a %s file; nothing written", e.Path, strings.Join(e.Locations, ", "), e.Format)
}

// Result is the audit record of one Apply. Marshal it to keep a log.
type Result struct {
	Source       string      `json:"source"`
	Dest         string      `json:"dest,omitempty"` // empty when there was nothing to remove
	Format       string      `json:"format"`
	Removed      []Edit      `json:"removed"`
	Unfixable    []Unfixable `json:"unfixable,omitempty"`
	SourceSHA256 string      `json:"source_sha256"`
	DestSHA256   string      `json:"dest_sha256,omitempty"`
	Attestation  Attestation `json:"attestation"`
	At           time.Time   `json:"at"`
}

// Apply writes a copy of src to dst with the planned tags removed. It never
// modifies src, never overwrites an existing dst, and writes nothing at all
// if the file declares provenance, if any planned removal is unsupported, or
// if the result still looks flagged. If there is nothing to remove it writes
// nothing and returns a Result with an empty Dest.
//
// Supported: PNG text chunks, JPEG comments, JPEG XMP CreatorTool/softwareAgent,
// EXIF ASCII tags (blanked in place), ID3v2.3/2.4 frames in MP3, Vorbis
// comments in FLAC, and RIFF INFO and bext text in WAV (blanked in place).
// Pixel, scan and audio data are copied verbatim.
func Apply(src, dst string, att Attestation) (*Result, error) {
	if !att.HumanMade {
		return nil, ErrNotAttested
	}
	plan, err := NewPlan(src)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	res := &Result{Source: src, Format: plan.Format, Removed: []Edit{}, Unfixable: plan.Unfixable,
		SourceSHA256: hex.EncodeToString(sum[:]), Attestation: att, At: time.Now().UTC()}
	if len(plan.Remove) == 0 {
		return res, nil
	}
	if _, err := os.Lstat(dst); err == nil {
		return nil, fmt.Errorf("%s already exists; refusing to overwrite", dst)
	}

	want := map[string]bool{}
	for _, e := range plan.Remove {
		want[e.Location] = true
	}
	var out []byte
	var covered map[string]bool
	switch plan.Format {
	case "png":
		out, covered, err = rewritePNG(data, want)
	case "jpeg":
		out, covered, err = rewriteJPEG(data, want)
	case "mp3", "mpeg-audio":
		out, covered, err = rewriteMP3(data, want)
	case "flac":
		out, covered, err = rewriteFLAC(data, want)
	case "wave":
		out, covered, err = rewriteWAV(data, want)
	default:
		err = &UnsupportedError{Path: src, Format: plan.Format, Locations: locations(plan.Remove, nil)}
	}
	if err != nil {
		return nil, err
	}
	if missing := locations(plan.Remove, covered); len(missing) > 0 {
		return nil, &UnsupportedError{Path: src, Format: plan.Format, Locations: missing}
	}

	if err := writeNew(dst, out, src, plan); err != nil {
		return nil, err
	}
	for _, e := range plan.Remove {
		res.Removed = append(res.Removed, e)
	}
	osum := sha256.Sum256(out)
	res.Dest, res.DestSHA256 = dst, hex.EncodeToString(osum[:])
	return res, nil
}

// locations returns the plan's locations not in skip, sorted.
func locations(edits []Edit, skip map[string]bool) []string {
	var out []string
	for _, e := range edits {
		if !skip[e.Location] {
			out = append(out, e.Location)
		}
	}
	sort.Strings(out)
	return out
}

// writeNew writes b to a temp file beside dst, checks that it no longer plans
// any removal and still has the same unfixable findings, then links it into
// place without clobbering anything.
func writeNew(dst string, b []byte, src string, plan *Plan) (err error) {
	f, err := os.CreateTemp(filepath.Dir(dst), ".aidetect-clean-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		os.Remove(tmp)
	}()
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if st, e := os.Stat(src); e == nil {
		os.Chmod(tmp, st.Mode().Perm())
	}
	chk, err := NewPlan(tmp)
	if err != nil {
		return fmt.Errorf("rewritten file failed verification: %w", err)
	}
	if len(chk.Remove) != 0 || len(chk.Unfixable) != len(plan.Unfixable) {
		return fmt.Errorf("rewritten file failed verification: still has %d removable and %d other findings (expected 0 and %d); nothing written",
			len(chk.Remove), len(chk.Unfixable), len(plan.Unfixable))
	}
	if err = os.Link(tmp, dst); err != nil {
		// no hard links on this filesystem: fall back, having already checked dst is free
		if _, e := os.Lstat(dst); e == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite", dst)
		}
		return os.Rename(tmp, dst)
	}
	return nil
}
