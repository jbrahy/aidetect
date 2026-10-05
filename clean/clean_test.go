package clean

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// ---------- fixture builders (PNG and JPEG are enough to exercise the policy) ----------

func pngChunk(typ string, data []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	copy(b[4:], typ)
	b = append(b, data...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(append([]byte(typ), data...)))
}

func pngFile(chunks ...[]byte) []byte {
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, pngChunk("IHDR", make([]byte, 13))...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	out = append(out, pngChunk("IDAT", make([]byte, 64))...)
	return append(out, pngChunk("IEND", nil)...)
}

func text(key, val string) []byte { return pngChunk("tEXt", []byte(key+"\x00"+val)) }

func jpegSeg(marker byte, data []byte) []byte {
	n := len(data) + 2
	return append([]byte{0xFF, marker, byte(n >> 8), byte(n)}, data...)
}

func jpegFile(segs ...[]byte) []byte {
	out := []byte{0xFF, 0xD8}
	for _, s := range segs {
		out = append(out, s...)
	}
	out = append(out, jpegSeg(0xDA, make([]byte, 10))...)
	return append(out, 0xFF, 0xD9)
}

func xmp(inner string) []byte {
	return []byte(`http://ns.adobe.com/xap/1.0/` + "\x00" + `<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description ` + inner + `/></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)
}

const dst = `Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/`

// c2paBlob fakes the JUMBF/CBOR bits aidetect looks at.
func c2paBlob() []byte {
	cbor := func(s string) []byte { return append([]byte{0x60 + byte(len(s))}, s...) }
	b := []byte("JP\x00\x01\x00\x00\x00\x01\x00\x00\x00\x40jumb\x00\x00\x00\x20jumdc2pa\x00")
	b = append(b, cbor("softwareAgent")...)
	return append(b, cbor("Camera")...)
}

func write(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------- tests ----------

func TestPlanRemovesStaleToolTag(t *testing.T) {
	p := write(t, "a.png", pngFile(text("Software", "Adobe Firefly"), text("Title", "Beach")))
	plan, err := NewPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Remove) != 1 || plan.Remove[0].Location != "PNG tEXt Software" {
		t.Fatalf("Remove = %+v, want exactly the Software tag", plan.Remove)
	}
	if len(plan.Unfixable) != 0 {
		t.Errorf("Unfixable = %+v, want none", plan.Unfixable)
	}
}

func TestPlanCleanFileIsEmpty(t *testing.T) {
	p := write(t, "b.png", pngFile(text("Software", "GIMP 2.10")))
	plan, err := NewPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Remove) != 0 || len(plan.Unfixable) != 0 {
		t.Errorf("plan = %+v, want empty", plan)
	}
}

func TestPlanRefusesProvenance(t *testing.T) {
	cases := map[string][]byte{
		"c2pa manifest":           jpegFile(jpegSeg(0xEB, c2paBlob())),
		"trained DigitalSource":   jpegFile(jpegSeg(0xE1, xmp(dst+`trainedAlgorithmicMedia"`))),
		"unrecognised DigitalSrc": jpegFile(jpegSeg(0xE1, xmp(dst+`somethingNew"`))),
		"IPTC AISystemUsed":       pngFile(text("AISystemUsed", "SomeModel")),
		"provenance plus stale tag": jpegFile(
			jpegSeg(0xE1, xmp(dst+`trainedAlgorithmicMedia" xmp:CreatorTool="Midjourney"`))),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			plan, err := NewPlan(write(t, "x.bin", data))
			var pe *ProvenanceError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want *ProvenanceError", err)
			}
			if len(pe.Findings) == 0 {
				t.Error("ProvenanceError lists no findings")
			}
			for _, f := range pe.Findings {
				if !f.Provenance {
					t.Errorf("non-provenance finding in error: %+v", f)
				}
			}
			if plan != nil {
				t.Errorf("plan = %+v, want nil when refused", plan)
			}
		})
	}
}

func TestPlanBenignDigitalSourceTypeDoesNotBlock(t *testing.T) {
	p := write(t, "c.jpg", jpegFile(jpegSeg(0xE1, xmp(dst+`digitalCapture" xmp:CreatorTool="Midjourney"`))))
	plan, err := NewPlan(p)
	if err != nil {
		t.Fatalf("benign DigitalSourceType blocked: %v", err)
	}
	if len(plan.Remove) != 1 {
		t.Fatalf("Remove = %+v, want the CreatorTool tag", plan.Remove)
	}
}

func TestPlanDoesNotOfferToRemoveGenerationParameters(t *testing.T) {
	// A parameter dump is evidence the image was generated, not a stale label.
	p := write(t, "d.png", pngFile(text("parameters", "a cat\nSteps: 30, Sampler: DPM++ 2M, CFG scale: 7, Seed: 1")))
	plan, err := NewPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Remove) != 0 {
		t.Errorf("Remove = %+v, want none", plan.Remove)
	}
	if len(plan.Unfixable) != 1 || plan.Unfixable[0].Reason == "" {
		t.Errorf("Unfixable = %+v, want the params finding with a reason", plan.Unfixable)
	}
}

func TestPlanMissingFile(t *testing.T) {
	if _, err := NewPlan(filepath.Join(t.TempDir(), "nope.png")); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestPlanNeverModifiesFile(t *testing.T) {
	data := pngFile(text("Software", "Adobe Firefly"))
	p := write(t, "e.png", data)
	if _, err := NewPlan(p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, data) {
		t.Error("NewPlan modified the file")
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}
