package aidetect

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- fixture builders ----------

func id3Frame23(id string, body []byte) []byte {
	h := make([]byte, 10)
	copy(h, id)
	binary.BigEndian.PutUint32(h[4:], uint32(len(body)))
	return append(h, body...)
}

func id3Tag(ver byte, frames ...[]byte) []byte {
	body := bytes.Join(frames, nil)
	body = append(body, make([]byte, 32)...) // padding
	n := len(body)
	h := []byte{'I', 'D', '3', ver, 0, 0, byte(n >> 21 & 0x7f), byte(n >> 14 & 0x7f), byte(n >> 7 & 0x7f), byte(n & 0x7f)}
	return append(h, body...)
}

func mp3(tag []byte) []byte {
	frame := append([]byte{0xFF, 0xFB, 0x90, 0x64}, make([]byte, 413)...)
	return append(tag, bytes.Repeat(frame, 4)...)
}

func utf16le(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func flacFile(comments ...string) []byte {
	var vc bytes.Buffer
	le := func(n int) { binary.Write(&vc, binary.LittleEndian, uint32(n)) }
	vendor := "reference libFLAC 1.4.3 20230623"
	le(len(vendor))
	vc.WriteString(vendor)
	le(len(comments))
	for _, c := range comments {
		le(len(c))
		vc.WriteString(c)
	}
	out := []byte("fLaC")
	out = append(out, 0x00, 0, 0, 34) // STREAMINFO
	out = append(out, make([]byte, 34)...)
	n := vc.Len()
	out = append(out, 0x84, byte(n>>16), byte(n>>8), byte(n)) // last, VORBIS_COMMENT
	out = append(out, vc.Bytes()...)
	return append(out, 0xFF, 0xF8, 0x00, 0x00)
}

func pngChunk(typ string, data []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	copy(b[4:], typ)
	b = append(b, data...)
	c := crc32.ChecksumIEEE(append([]byte(typ), data...))
	return binary.BigEndian.AppendUint32(b, c)
}

func pngFile(chunks ...[]byte) []byte {
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, pngChunk("IHDR", make([]byte, 13))...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	out = append(out, pngChunk("IDAT", bytes.Repeat([]byte("suno midjourney "), 64))...) // essence must be ignored
	return append(out, pngChunk("IEND", nil)...)
}

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
	out = append(out, bytes.Repeat([]byte("openai "), 50)...) // scan data must be ignored
	return append(out, 0xFF, 0xD9)
}

func xmp(inner string) []byte {
	return []byte(`http://ns.adobe.com/xap/1.0/` + "\x00" + `<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description ` + inner + `/></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)
}

func box(typ string, children ...[]byte) []byte {
	body := bytes.Join(children, nil)
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(8+len(body)))
	copy(b[4:], typ)
	return append(b, body...)
}

func mp4File(tool string) []byte {
	data := append([]byte{0, 0, 0, 1, 0, 0, 0, 0}, tool...)
	ilst := box("ilst", box("\xa9too", box("data", data)))
	hdlr := box("hdlr", make([]byte, 25))
	meta := box("meta", append([]byte{0, 0, 0, 0}, append(hdlr, ilst...)...))
	return bytes.Join([][]byte{
		box("ftyp", []byte("isom\x00\x00\x02\x00isomiso2mp41")),
		box("moov", box("udta", meta)),
		box("mdat", bytes.Repeat([]byte("sora openai "), 20)),
	}, nil)
}

func wavFile(rate int, pcm []float64) []byte {
	var b bytes.Buffer
	w := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	b.WriteString("RIFF")
	w(uint32(36 + len(pcm)*2))
	b.WriteString("WAVEfmt ")
	w(uint32(16))
	w(uint16(1))
	w(uint16(1))
	w(uint32(rate))
	w(uint32(rate * 2))
	w(uint16(2))
	w(uint16(16))
	b.WriteString("data")
	w(uint32(len(pcm) * 2))
	for _, v := range pcm {
		w(int16(math.Max(-1, math.Min(1, v)) * 32767))
	}
	return b.Bytes()
}

// synthMusic: noise bed + short random notes (with harmonics) that change
// every 250 ms, like real music. artifacts adds a fixed comb of faint HF tones.
func synthMusic(rate int, seconds float64, artifacts bool) []float64 {
	rng := rand.New(rand.NewSource(1))
	n := int(float64(rate) * seconds)
	out := make([]float64, n)
	noteLen := rate / 4
	var f0 float64
	for i := 0; i < n; i++ {
		if i%noteLen == 0 {
			f0 = 110 * math.Pow(2, float64(rng.Intn(48))/12)
		}
		t := float64(i) / float64(rate)
		env := math.Exp(-float64(i%noteLen) / float64(noteLen) * 3)
		v := 0.0
		for h := 1; h <= 8; h++ {
			v += math.Sin(2*math.Pi*f0*float64(h)*t) / float64(h)
		}
		out[i] = 0.25*env*v + 0.05*rng.NormFloat64()
		if artifacts {
			for k := 5; k <= 18; k++ {
				out[i] += 0.002 * math.Sin(2*math.Pi*float64(k)*1000.0*t)
			}
		}
	}
	return out
}

func inspectBytes(t *testing.T, name string, b []byte) Report {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return Inspect(p, Options{Spectral: true})
}

func hasDetail(r Report, sub string) bool {
	for _, f := range r.Findings {
		if strings.Contains(f.Detail, sub) {
			return true
		}
	}
	return false
}

// ---------- tests ----------

func TestContainers(t *testing.T) {
	cases := []struct {
		name, file string
		data       []byte
		format     string
		verdict    string
		want       string
	}{
		{"mp3 id3v2.3 encoder", "a.mp3", mp3(id3Tag(3,
			id3Frame23("TIT2", append([]byte{0}, "Big Mouf"...)),
			id3Frame23("TSSE", append([]byte{0}, "Suno v4.5"...)))),
			"mp3", VerdictDeclared, "Suno"},
		{"mp3 id3v2.3 utf16 comment", "b.mp3", mp3(id3Tag(3,
			id3Frame23("COMM", append(append([]byte{1, 'e', 'n', 'g'}, append(utf16le(""), 0, 0)...), utf16le("made with Udio")...)))),
			"mp3", VerdictDeclared, "Udio"},
		{"mp3 clean", "c.mp3", mp3(id3Tag(3,
			id3Frame23("TIT2", append([]byte{0}, "Studio Audio Session"...)),
			id3Frame23("COMM", append([]byte{0, 'e', 'n', 'g', 0}, "mixed loudly at the studio"...)),
			id3Frame23("TSSE", append([]byte{0}, "LAME 3.100"...)))),
			"mp3", VerdictNone, ""},
		{"flac vorbis comment", "d.flac", flacFile("TITLE=Forever Home", "COMMENT=Created with Stable Audio 2.0"),
			"flac", VerdictDeclared, "Stable Audio"},
		{"flac encoder field non-strict", "e.flac", flacFile("ENCODER=Loudly"),
			"flac", VerdictDeclared, "Loudly"},
		{"flac clean", "f.flac", flacFile("TITLE=Forever Home", "ARTIST=Big Mouf"),
			"flac", VerdictNone, ""},
		{"png a1111", "g.png", pngFile(pngChunk("tEXt", []byte("parameters\x00a cat\nSteps: 30, Sampler: DPM++ 2M, CFG scale: 7, Seed: 1"))),
			"png", VerdictDeclared, "Stable Diffusion WebUI"},
		{"png comfyui", "h.png", pngFile(pngChunk("tEXt", []byte(`prompt`+"\x00"+`{"3":{"class_type":"KSampler"}}`))),
			"png", VerdictDeclared, "ComfyUI"},
		{"png clean (essence ignored)", "i.png", pngFile(pngChunk("tEXt", []byte("Software\x00GIMP 2.10"))),
			"png", VerdictNone, ""},
		{"jpeg xmp trained", "j.jpg", jpegFile(jpegSeg(0xE1, xmp(`Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"`))),
			"jpeg", VerdictDeclared, "trainedAlgorithmicMedia"},
		{"jpeg xmp capture", "k.jpg", jpegFile(jpegSeg(0xE1, xmp(`Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture" xmp:CreatorTool="Adobe Lightroom"`))),
			"jpeg", VerdictNone, "digitalCapture"},
		{"jpeg xmp creator tool", "l.jpg", jpegFile(jpegSeg(0xE1, xmp(`xmp:CreatorTool="Midjourney"`))),
			"jpeg", VerdictDeclared, "Midjourney"},
		{"jpeg c2pa softwareAgent map", "m.jpg", jpegFile(jpegSeg(0xEB, c2paBlob("Firefly"))),
			"jpeg", VerdictDeclared, "Firefly"},
		{"mp4 ilst tool non-strict", "n.mp4", mp4File("Sora"), "isobmff", VerdictDeclared, "Sora"},
		{"mp4 clean (mdat ignored)", "o.mp4", mp4File("Lavf61.7.100"), "isobmff", VerdictNone, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := inspectBytes(t, tc.file, tc.data)
			if r.Format != tc.format {
				t.Errorf("format = %q, want %q", r.Format, tc.format)
			}
			if r.Verdict != tc.verdict {
				j, _ := json.MarshalIndent(r, "", "  ")
				t.Errorf("verdict = %s, want %s\n%s", r.Verdict, tc.verdict, j)
			}
			if tc.want != "" && !hasDetail(r, tc.want) {
				j, _ := json.MarshalIndent(r, "", "  ")
				t.Errorf("no finding mentions %q\n%s", tc.want, j)
			}
		})
	}
}

// c2paBlob fakes the bits of an APP11 JUMBF C2PA segment we look at: JUMBF
// box types, the c2pa label, and a CBOR action with a v2 softwareAgent map.
func c2paBlob(agent string) []byte {
	var b []byte
	b = append(b, "JP\x00\x01\x00\x00\x00\x01\x00\x00\x00\x40jumb\x00\x00\x00\x20jumdc2pa\x00"...)
	b = append(b, cborText("action")...)
	b = append(b, cborText("c2pa.created")...)
	b = append(b, cborText("digitalSourceType")...)
	b = append(b, cborText("http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia")...)
	b = append(b, cborText("softwareAgent")...)
	b = append(b, 0xA1)
	b = append(b, cborText("name")...)
	return append(b, cborText(agent)...)
}

func TestSignatureBoundaries(t *testing.T) {
	no := []string{"Studio", "Audio Interface", "Laudio", "sunology", "fluxcapacitor", "Soraya", "grokking"}
	for _, s := range no {
		if m := matchSignatures(s, true); len(m) > 0 {
			t.Errorf("%q matched %s", s, m[0].Name)
		}
	}
	yes := map[string]string{"Suno": "Suno", "udio.com": "Udio", "DALL-E 3": "DALL·E", "FLUX.1 [dev]": "FLUX", "stable-diffusion-xl": "Stable Diffusion"}
	for s, want := range yes {
		m := matchSignatures(s, true)
		if len(m) == 0 || m[0].Name != want {
			t.Errorf("%q: got %v, want %s", s, m, want)
		}
	}
	if m := matchSignatures("shot on location with Sora", false); len(m) > 0 {
		t.Errorf("non-strict signature matched in free text: %s", m[0].Name)
	}
}

func TestSpectral(t *testing.T) {
	const rate = 44100
	clean := inspectBytes(t, "clean.wav", wavFile(rate, synthMusic(rate, 20, false)))
	art := inspectBytes(t, "art.wav", wavFile(rate, synthMusic(rate, 20, true)))
	if clean.Spectral == nil || art.Spectral == nil {
		t.Fatalf("no spectral metrics: %v %v", clean.Errors, art.Errors)
	}
	t.Logf("clean: %+v", *clean.Spectral)
	t.Logf("artifact: %+v", *art.Spectral)
	if clean.Verdict != VerdictNone {
		t.Errorf("clean verdict = %s", clean.Verdict)
	}
	if art.Verdict != VerdictSuspicious {
		t.Errorf("artifact verdict = %s, want %s", art.Verdict, VerdictSuspicious)
	}
	if art.Spectral.CombSpacingHz < 900 || art.Spectral.CombSpacingHz > 1100 {
		t.Errorf("comb spacing = %.1f, want ≈1000", art.Spectral.CombSpacingHz)
	}
}

func TestHiveParsing(t *testing.T) {
	body := `{"status":[{"response":{"output":[
		{"time":0,"classes":[{"class":"ai_generated","score":0.42},{"class":"not_ai_generated","score":0.58},{"class":"suno","score":0.1}]},
		{"time":1,"classes":[{"class":"ai_generated","score":0.97},{"class":"not_ai_generated","score":0.03},{"class":"suno","score":0.91}]}]}}]}`
	var doc any
	json.Unmarshal([]byte(body), &doc)
	s := map[string]float64{}
	walkClasses(doc, s)
	if s["ai_generated"] != 0.97 {
		t.Errorf("ai_generated = %v", s["ai_generated"])
	}
	if got := topSource(s); !strings.Contains(got, "suno") {
		t.Errorf("topSource = %q", got)
	}
}

func TestID3v24Syncsafe(t *testing.T) {
	body := append([]byte{3}, "ElevenLabs Music"...)
	n := len(body)
	fr := append([]byte{'T', 'E', 'N', 'C', 0, 0, byte(n >> 7), byte(n & 0x7f), 0, 0}, body...)
	r := inspectBytes(t, "v24.mp3", mp3(id3Tag(4, fr)))
	if r.Verdict != VerdictDeclared || !hasDetail(r, "ElevenLabs") {
		j, _ := json.MarshalIndent(r, "", "  ")
		t.Errorf("v2.4 TENC not detected\n%s", j)
	}
}

// Parsers take attacker-controlled bytes: truncating or corrupting any
// fixture must never panic.
func TestNoPanicOnMalformed(t *testing.T) {
	fixtures := [][]byte{
		mp3(id3Tag(3, id3Frame23("TSSE", append([]byte{1}, utf16le("Suno")...)))),
		mp3(id3Tag(4, id3Frame23("TXXX", []byte{3, 'a', 0, 'b'}))),
		flacFile("ENCODER=x"), pngFile(pngChunk("iTXt", []byte("k\x00\x01\x00en\x00\x00zz"))),
		jpegFile(jpegSeg(0xE1, append([]byte("Exif\x00\x00II*\x00\x08\x00\x00\x00"), 0xFF, 0xFF))),
		jpegFile(jpegSeg(0xEB, c2paBlob("x"))), mp4File("Lavf"),
		wavFile(8000, make([]float64, 100)),
	}
	rng := rand.New(rand.NewSource(3))
	dir := t.TempDir()
	for _, fx := range fixtures {
		for n := 0; n <= len(fx); n += 1 + len(fx)/200 {
			try(t, dir, fx[:n])
		}
		for i := 0; i < 200; i++ {
			b := append([]byte(nil), fx...)
			for j := 0; j < 1+rng.Intn(8); j++ {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
			try(t, dir, b)
		}
	}
}

func try(t *testing.T, dir string, b []byte) {
	t.Helper()
	p := filepath.Join(dir, "x")
	os.WriteFile(p, b, 0o644)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on %d-byte input %x…: %v", len(b), b[:min(len(b), 32)], r)
		}
	}()
	Inspect(p, Options{Spectral: true})
}
