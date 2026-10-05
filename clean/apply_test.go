package clean

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var human = Attestation{HumanMade: true, Note: "photographed by me"}

func tmp(t *testing.T) string { return t.TempDir() }

func readAll(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func notExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("%s exists, want it not written (stat err = %v)", p, err)
	}
}

// pngIDAT returns the concatenated IDAT payloads, i.e. the pixels.
func pngIDAT(b []byte) []byte {
	var out []byte
	for off := 8; off+12 <= len(b); {
		n := int(binary.BigEndian.Uint32(b[off:]))
		if string(b[off+4:off+8]) == "IDAT" {
			out = append(out, b[off+8:off+8+n]...)
		}
		off += 12 + n
	}
	return out
}

func sos(b []byte) []byte { return b[bytes.Index(b, []byte{0xFF, 0xDA}):] }

func TestApplyPNGRemovesOnlyTheStaleTag(t *testing.T) {
	dir := tmp(t)
	data := pngFile(text("Title", "Beach"), text("Software", "Adobe Firefly"), text("Author", "Sam"))
	src := filepath.Join(dir, "in.png")
	os.WriteFile(src, data, 0o644)
	dst := filepath.Join(dir, "out.png")

	res, err := Apply(src, dst, human)
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, dst)
	if bytes.Contains(out, []byte("Firefly")) {
		t.Error("tag still present")
	}
	if !bytes.Contains(out, []byte("Beach")) || !bytes.Contains(out, []byte("Sam")) {
		t.Error("an unrelated tag was removed")
	}
	if !bytes.Equal(pngIDAT(out), pngIDAT(data)) {
		t.Error("pixel data changed")
	}
	if !bytes.Equal(readAll(t, src), data) {
		t.Error("original was modified")
	}
	if len(res.Removed) != 1 || !res.Attestation.HumanMade || res.Attestation.Note != human.Note {
		t.Errorf("result = %+v", res)
	}
	if got := sha256.Sum256(out); res.DestSHA256 != hexOf(got[:]) {
		t.Error("DestSHA256 does not match the written file")
	}
	if plan, err := NewPlan(dst); err != nil || len(plan.Remove) != 0 {
		t.Errorf("output still flagged: %+v %v", plan, err)
	}
}

func TestApplyPNGKeepsSecondChunkWithSameKeyThatIsNotAGenerator(t *testing.T) {
	dir := tmp(t)
	src := filepath.Join(dir, "in.png")
	os.WriteFile(src, pngFile(text("Software", "Adobe Firefly"), text("Software", "GIMP 2.10")), 0o644)
	if _, err := Apply(src, filepath.Join(dir, "out.png"), human); err != nil {
		t.Fatal(err)
	}
	out := readAll(t, filepath.Join(dir, "out.png"))
	if bytes.Contains(out, []byte("Firefly")) || !bytes.Contains(out, []byte("GIMP")) {
		t.Error("removed the wrong Software chunk")
	}
}

func TestApplyRequiresAttestation(t *testing.T) {
	dir := tmp(t)
	src := filepath.Join(dir, "in.png")
	os.WriteFile(src, pngFile(text("Software", "Adobe Firefly")), 0o644)
	dst := filepath.Join(dir, "out.png")
	for _, a := range []Attestation{{}, {Note: "no flag"}} {
		if _, err := Apply(src, dst, a); !errors.Is(err, ErrNotAttested) {
			t.Errorf("err = %v, want ErrNotAttested", err)
		}
	}
	notExist(t, dst)
}

func TestApplyRefusesProvenanceAndWritesNothing(t *testing.T) {
	dir := tmp(t)
	src := filepath.Join(dir, "in.jpg")
	os.WriteFile(src, jpegFile(jpegSeg(0xE1, xmp(dst+`trainedAlgorithmicMedia" xmp:CreatorTool="Midjourney"`))), 0o644)
	out := filepath.Join(dir, "out.jpg")
	_, err := Apply(src, out, human)
	var pe *ProvenanceError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *ProvenanceError", err)
	}
	notExist(t, out)
}

func TestApplyNeverOverwritesOrWritesInPlace(t *testing.T) {
	dir := tmp(t)
	src := filepath.Join(dir, "in.png")
	data := pngFile(text("Software", "Adobe Firefly"))
	os.WriteFile(src, data, 0o644)
	if _, err := Apply(src, src, human); err == nil {
		t.Error("Apply to the same path succeeded")
	}
	existing := filepath.Join(dir, "exists.png")
	os.WriteFile(existing, []byte("keep me"), 0o644)
	if _, err := Apply(src, existing, human); err == nil {
		t.Error("Apply over an existing file succeeded")
	}
	if string(readAll(t, existing)) != "keep me" || !bytes.Equal(readAll(t, src), data) {
		t.Error("a file was modified")
	}
	link := filepath.Join(dir, "link.png")
	if err := os.Symlink(src, link); err == nil {
		if _, err := Apply(src, link, human); err == nil {
			t.Error("Apply onto a symlink to the source succeeded")
		}
	}
}

func TestApplyNothingToRemoveWritesNothing(t *testing.T) {
	dir := tmp(t)
	src := filepath.Join(dir, "in.png")
	os.WriteFile(src, pngFile(text("Software", "GIMP 2.10")), 0o644)
	out := filepath.Join(dir, "out.png")
	res, err := Apply(src, out, human)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 0 {
		t.Errorf("Removed = %+v", res.Removed)
	}
	notExist(t, out)
}

func TestApplyKeepsUnfixableFindings(t *testing.T) {
	dir := tmp(t)
	src := filepath.Join(dir, "in.png")
	os.WriteFile(src, pngFile(text("Software", "Adobe Firefly"),
		text("parameters", "a cat\nSteps: 30, Sampler: DPM++ 2M, CFG scale: 7, Seed: 1")), 0o644)
	out := filepath.Join(dir, "out.png")
	res, err := Apply(src, out, human)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 || len(res.Unfixable) != 1 {
		t.Errorf("result = %+v", res)
	}
	if !bytes.Contains(readAll(t, out), []byte("Steps: 30")) {
		t.Error("the parameter dump was removed")
	}
}

func TestApplyJPEGComment(t *testing.T) {
	dir := tmp(t)
	data := jpegFile(jpegSeg(0xFE, []byte("made with Midjourney")), jpegSeg(0xE1, xmp(`dc:title="Beach"`)))
	src, out := filepath.Join(dir, "in.jpg"), filepath.Join(dir, "out.jpg")
	os.WriteFile(src, data, 0o644)
	if _, err := Apply(src, out, human); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, out)
	if bytes.Contains(got, []byte("Midjourney")) || !bytes.Contains(got, []byte("Beach")) {
		t.Error("wrong segments removed")
	}
	if !bytes.Equal(sos(got), sos(data)) {
		t.Error("scan data changed")
	}
}

func TestApplyJPEGXMPAttributeAndElementForms(t *testing.T) {
	dir := tmp(t)
	attr := xmp(`dc:title="Beach" xmp:CreatorTool="Midjourney" xmp:Rating="5"`)
	elem := []byte(`http://ns.adobe.com/xap/1.0/` + "\x00" + `<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description dc:title="Beach"><xmp:CreatorTool>Adobe Firefly</xmp:CreatorTool></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)
	for name, packet := range map[string][]byte{"attribute": attr, "element": elem} {
		t.Run(name, func(t *testing.T) {
			data := jpegFile(jpegSeg(0xE1, packet))
			src, out := filepath.Join(dir, name+".jpg"), filepath.Join(dir, name+"-out.jpg")
			os.WriteFile(src, data, 0o644)
			if _, err := Apply(src, out, human); err != nil {
				t.Fatal(err)
			}
			got := readAll(t, out)
			if bytes.Contains(got, []byte("CreatorTool")) {
				t.Errorf("tool field still present: %s", got)
			}
			if !bytes.Contains(got, []byte(`dc:title="Beach"`)) {
				t.Error("unrelated attribute removed")
			}
			if name == "attribute" && !bytes.Contains(got, []byte(`xmp:Rating="5"`)) {
				t.Error("neighbouring attribute removed")
			}
			if !bytes.Equal(sos(got), sos(data)) {
				t.Error("scan data changed")
			}
			// segment length must match the shrunken payload: re-planning parses it
			if plan, err := NewPlan(out); err != nil || len(plan.Remove) != 0 {
				t.Errorf("output not clean: %+v %v", plan, err)
			}
		})
	}
}

func exifApp1(software string) []byte {
	v := append([]byte(software), 0)
	t := []byte("II*\x00\x08\x00\x00\x00\x01\x00")
	e := make([]byte, 12)
	binary.LittleEndian.PutUint16(e, 0x0131)
	binary.LittleEndian.PutUint16(e[2:], 2)
	binary.LittleEndian.PutUint32(e[4:], uint32(len(v)))
	binary.LittleEndian.PutUint32(e[8:], 26)
	t = append(t, e...)
	t = append(t, 0, 0, 0, 0)
	return append(append([]byte("Exif\x00\x00"), t...), v...)
}

func TestApplyEXIFSoftwareBlankedInPlace(t *testing.T) {
	dir := tmp(t)
	data := jpegFile(jpegSeg(0xE1, exifApp1("Midjourney v6")))
	src, out := filepath.Join(dir, "in.jpg"), filepath.Join(dir, "out.jpg")
	os.WriteFile(src, data, 0o644)
	if _, err := Apply(src, out, human); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, out)
	if bytes.Contains(got, []byte("Midjourney")) {
		t.Error("EXIF Software still present")
	}
	if len(got) != len(data) {
		t.Errorf("length changed %d -> %d; EXIF is blanked in place", len(data), len(got))
	}
}

func TestApplyEmptyDestinationDirIsAnError(t *testing.T) {
	dir := tmp(t)
	src := filepath.Join(dir, "in.png")
	os.WriteFile(src, pngFile(text("Software", "Adobe Firefly")), 0o644)
	if _, err := Apply(src, filepath.Join(dir, "missing-dir", "out.png"), human); err == nil {
		t.Error("want error for destination in a missing directory")
	}
}

func TestApplyUnsupportedLocationWritesNothing(t *testing.T) {
	// XMP inside a PNG iTXt chunk is flagged by aidetect but not rewritable here.
	itxt := pngChunk("iTXt", append([]byte("XML:com.adobe.xmp\x00\x00\x00\x00\x00"),
		`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description xmp:CreatorTool="Midjourney"/></rdf:RDF></x:xmpmeta>`...))
	dir := tmp(t)
	src, out := filepath.Join(dir, "in.png"), filepath.Join(dir, "out.png")
	data := pngFile(itxt)
	os.WriteFile(src, data, 0o644)
	_, err := Apply(src, out, human)
	var ue *UnsupportedError
	if !errors.As(err, &ue) || len(ue.Locations) == 0 {
		t.Fatalf("err = %v, want *UnsupportedError", err)
	}
	notExist(t, out)
	if !bytes.Equal(readAll(t, src), data) {
		t.Error("original modified")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".aidetect-clean-*")); len(left) > 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

func TestApplyOutputStillDecodesToSamePixels(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for i := range img.Pix {
		img.Pix[i] = byte(i * 7)
	}
	var pb, jb bytes.Buffer
	png.Encode(&pb, img)
	jpeg.Encode(&jb, img, nil)
	// inject a flagged tag right after the PNG signature+IHDR / the JPEG SOI
	p := pb.Bytes()
	pngData := append(append(append([]byte(nil), p[:33]...), text("Software", "Adobe Firefly")...), p[33:]...)
	j := jb.Bytes()
	jpgData := append(append(append([]byte(nil), j[:2]...), jpegSeg(0xFE, []byte("made with Midjourney"))...), j[2:]...)

	dir := tmp(t)
	for name, data := range map[string][]byte{"in.png": pngData, "in.jpg": jpgData} {
		src := filepath.Join(dir, name)
		out := filepath.Join(dir, "out-"+name)
		os.WriteFile(src, data, 0o644)
		if _, err := Apply(src, out, human); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		a, _, err1 := image.Decode(bytes.NewReader(data))
		b, _, err2 := image.Decode(bytes.NewReader(readAll(t, out)))
		if err1 != nil || err2 != nil {
			t.Fatalf("%s: decode before=%v after=%v", name, err1, err2)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: pixels differ after cleaning", name)
		}
	}
}

func TestApplyRemovesEveryFieldWhenOneGeneratorIsNamedTwice(t *testing.T) {
	data := mp3File(id3Tag(3, 0,
		textFrame(3, "TIT2", "Big Mouf"),
		textFrame(3, "TSSE", "Suno v4.5"),
		textFrame(3, "TENC", "Suno"),
		id3Frame(3, "COMM", append([]byte{0, 'e', 'n', 'g', 0}, "made with Suno"...))))
	out, res, err := run1(t, "m.mp3", data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("Suno")) || len(res.Removed) != 3 {
		t.Errorf("removed %+v, Suno left: %v", res.Removed, bytes.Contains(out, []byte("Suno")))
	}
}
