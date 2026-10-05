package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pngChunk(typ string, data []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	copy(b[4:], typ)
	b = append(b, data...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(append([]byte(typ), data...)))
}

func pngFile(chunks ...[]byte) []byte {
	out := append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", make([]byte, 13))...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return append(append(out, pngChunk("IDAT", make([]byte, 32))...), pngChunk("IEND", nil)...)
}

func text(k, v string) []byte { return pngChunk("tEXt", []byte(k+"\x00"+v)) }

func jpegWithTrainedXMP() []byte {
	x := `http://ns.adobe.com/xap/1.0/` + "\x00" + `<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"/></rdf:RDF></x:xmpmeta>`
	n := len(x) + 2
	out := []byte{0xFF, 0xD8, 0xFF, 0xE1, byte(n >> 8), byte(n)}
	out = append(out, x...)
	return append(out, 0xFF, 0xDA, 0, 4, 0, 0, 0xFF, 0xD9)
}

func setup(t *testing.T, name string, data []byte) (src, dst, dir string) {
	t.Helper()
	dir = t.TempDir()
	src = filepath.Join(dir, name)
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return src, filepath.Join(dir, "out-"+name), dir
}

func do(args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestPlanModeWritesNothingAndNeedsNoAttestation(t *testing.T) {
	src, dst, _ := setup(t, "a.png", pngFile(text("Software", "Adobe Firefly")))
	code, out, _ := do("-plan", src, dst)
	if code != 0 || !strings.Contains(out, "PNG tEXt Software") {
		t.Errorf("code=%d out=%q", code, out)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("-plan wrote a file")
	}
}

func TestWritingRequiresAttestationFlag(t *testing.T) {
	src, dst, _ := setup(t, "a.png", pngFile(text("Software", "Adobe Firefly")))
	code, _, errOut := do(src, dst)
	if code != 1 || !strings.Contains(errOut, "attest") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("wrote without attestation")
	}
}

func TestCleanWritesCopyAndLog(t *testing.T) {
	src, dst, dir := setup(t, "a.png", pngFile(text("Software", "Adobe Firefly"), text("Title", "Beach")))
	logp := filepath.Join(dir, "clean.log")
	code, out, errOut := do("-attest-human-made", "-note", "my photo", "-log", logp, src, dst)
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	if b, _ := os.ReadFile(dst); bytes.Contains(b, []byte("Firefly")) || !bytes.Contains(b, []byte("Beach")) {
		t.Error("output wrong")
	}
	if !strings.Contains(out, "removed") {
		t.Errorf("out = %q", out)
	}
	var rec struct {
		Source      string
		Removed     []map[string]any
		Attestation struct {
			HumanMade bool   `json:"human_made"`
			Note      string `json:"note"`
		}
	}
	lb, _ := os.ReadFile(logp)
	if err := json.Unmarshal(bytes.TrimSpace(lb), &rec); err != nil {
		t.Fatalf("log not one JSON line: %v\n%s", err, lb)
	}
	if rec.Source != src || len(rec.Removed) != 1 || !rec.Attestation.HumanMade || rec.Attestation.Note != "my photo" {
		t.Errorf("log = %+v", rec)
	}
	// a second run appends
	src2, dst2, _ := setup(t, "b.png", pngFile(text("Software", "Midjourney")))
	do("-attest-human-made", "-log", logp, src2, dst2)
	if lines := bytes.Count(bytes.TrimSpace(mustRead(t, logp)), []byte("\n")) + 1; lines != 2 {
		t.Errorf("log has %d lines, want 2", lines)
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProvenanceRefusedWithExit2AndExplanation(t *testing.T) {
	src, dst, _ := setup(t, "a.jpg", jpegWithTrainedXMP())
	for _, args := range [][]string{{"-attest-human-made", src, dst}, {"-plan", src, dst}} {
		code, _, errOut := do(args...)
		if code != 2 || !strings.Contains(errOut, "provenance") {
			t.Errorf("%v: code=%d err=%q", args, code, errOut)
		}
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("wrote a refused file")
	}
}

func TestNothingToRemove(t *testing.T) {
	src, dst, _ := setup(t, "a.png", pngFile(text("Software", "GIMP 2.10")))
	code, out, _ := do("-attest-human-made", src, dst)
	if code != 0 || !strings.Contains(out, "nothing to remove") {
		t.Errorf("code=%d out=%q", code, out)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("wrote a file with nothing to remove")
	}
}

func TestUnsupportedExit3(t *testing.T) {
	itxt := pngChunk("iTXt", append([]byte("XML:com.adobe.xmp\x00\x00\x00\x00\x00"),
		`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description xmp:CreatorTool="Midjourney"/></rdf:RDF></x:xmpmeta>`...))
	src, dst, _ := setup(t, "a.png", pngFile(itxt))
	if code, _, errOut := do("-attest-human-made", src, dst); code != 3 {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"only-one"}, {"-plan"}} {
		if code, _, _ := do(args...); code != 1 {
			t.Errorf("%v: code=%d, want 1", args, code)
		}
	}
	if code, _, _ := do("-plan", "/nonexistent/x.png", "/tmp/y.png"); code != 1 {
		t.Error("missing file should exit 1")
	}
}
