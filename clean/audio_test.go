package clean

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func id3Frame(ver byte, id string, body []byte) []byte {
	h := make([]byte, 10)
	copy(h, id)
	if ver == 4 {
		n := len(body)
		copy(h[4:], []byte{byte(n >> 21 & 0x7f), byte(n >> 14 & 0x7f), byte(n >> 7 & 0x7f), byte(n & 0x7f)})
	} else {
		binary.BigEndian.PutUint32(h[4:], uint32(len(body)))
	}
	return append(h, body...)
}

func textFrame(ver byte, id, s string) []byte { return id3Frame(ver, id, append([]byte{0}, s...)) }

func id3Tag(ver, flags byte, frames ...[]byte) []byte {
	body := append(bytes.Join(frames, nil), make([]byte, 32)...)
	n := len(body)
	h := []byte{'I', 'D', '3', ver, 0, flags, byte(n >> 21 & 0x7f), byte(n >> 14 & 0x7f), byte(n >> 7 & 0x7f), byte(n & 0x7f)}
	return append(h, body...)
}

var mpegFrames = bytes.Repeat(append([]byte{0xFF, 0xFB, 0x90, 0x64}, make([]byte, 413)...), 4)

func mp3File(tag []byte, tail ...byte) []byte {
	return append(append(append([]byte(nil), tag...), mpegFrames...), tail...)
}

func run1(t *testing.T, name string, data []byte) (out []byte, res *Result, err error) {
	t.Helper()
	dir := t.TempDir()
	src, dst := filepath.Join(dir, name), filepath.Join(dir, "out-"+name)
	os.WriteFile(src, data, 0o644)
	res, err = Apply(src, dst, human)
	if err == nil && res.Dest != "" {
		out = readAll(t, dst)
	}
	return
}

func TestApplyMP3RemovesFlaggedFramesKeepsSizeAndAudio(t *testing.T) {
	for _, ver := range []byte{3, 4} {
		tag := id3Tag(ver, 0,
			textFrame(ver, "TIT2", "Big Mouf"),
			textFrame(ver, "TSSE", "Suno v4.5"),
			id3Frame(ver, "COMM", append([]byte{0, 'e', 'n', 'g', 0}, "made with Udio"...)),
			textFrame(ver, "TPE1", "Levi"))
		data := mp3File(tag)
		out, res, err := run1(t, "a.mp3", data)
		if err != nil {
			t.Fatalf("v2.%d: %v", ver, err)
		}
		if bytes.Contains(out, []byte("Suno")) || bytes.Contains(out, []byte("Udio")) {
			t.Errorf("v2.%d: flagged frames remain", ver)
		}
		if !bytes.Contains(out, []byte("Big Mouf")) || !bytes.Contains(out, []byte("Levi")) {
			t.Errorf("v2.%d: unrelated frames lost", ver)
		}
		if len(out) != len(data) {
			t.Errorf("v2.%d: file length %d -> %d; tag must keep its size", ver, len(data), len(out))
		}
		if !bytes.HasSuffix(out, mpegFrames) {
			t.Errorf("v2.%d: audio changed", ver)
		}
		if len(res.Removed) != 2 {
			t.Errorf("v2.%d: removed %+v", ver, res.Removed)
		}
	}
}

func TestApplyMP3UnsupportedPlacesWriteNothing(t *testing.T) {
	v1 := append([]byte("TAG"), make([]byte, 125)...)
	copy(v1[3+30+30+30+4:], "made with Suno")
	cases := map[string][]byte{
		"ID3v1 comment":      mp3File(id3Tag(3, 0, textFrame(3, "TIT2", "x")), v1...),
		"unsynchronised tag": mp3File(id3Tag(3, 0x80, textFrame(3, "TSSE", "Suno v4.5"))),
		"ID3v2.2":            mp3File(id3Tag(2, 0, []byte("TSS\x00\x00\x0a\x00Suno v4.5"))),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := run1(t, "b.mp3", data)
			var ue *UnsupportedError
			if !errors.As(err, &ue) {
				t.Errorf("err = %v, want *UnsupportedError", err)
			}
		})
	}
}

func flacWith(vendor string, comments ...string) []byte {
	var vc bytes.Buffer
	le := func(n int) { binary.Write(&vc, binary.LittleEndian, uint32(n)) }
	le(len(vendor))
	vc.WriteString(vendor)
	le(len(comments))
	for _, c := range comments {
		le(len(c))
		vc.WriteString(c)
	}
	out := append([]byte("fLaC"), 0x00, 0, 0, 34)
	out = append(out, make([]byte, 34)...)
	n := vc.Len()
	out = append(out, 0x84, byte(n>>16), byte(n>>8), byte(n))
	out = append(out, vc.Bytes()...)
	return append(out, 0xFF, 0xF8, 0x12, 0x34, 0x56)
}

func TestApplyFLACRemovesFlaggedCommentsOnly(t *testing.T) {
	data := flacWith("reference libFLAC 1.4.3", "TITLE=Forever Home", "COMMENT=Created with Stable Audio 2.0", "ENCODER=Loudly", "ARTIST=Big Mouf")
	out, res, err := run1(t, "a.flac", data)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"Stable Audio", "Loudly"} {
		if bytes.Contains(out, []byte(gone)) {
			t.Errorf("%s remains", gone)
		}
	}
	for _, kept := range []string{"Forever Home", "Big Mouf", "libFLAC"} {
		if !bytes.Contains(out, []byte(kept)) {
			t.Errorf("%s lost", kept)
		}
	}
	if !bytes.HasSuffix(out, []byte{0xFF, 0xF8, 0x12, 0x34, 0x56}) {
		t.Error("audio frames changed")
	}
	if out[4+4+34] != 0x84 {
		t.Errorf("last-block flag or type byte = %#x, want 0x84", out[4+4+34])
	}
	if len(res.Removed) != 2 {
		t.Errorf("removed %+v", res.Removed)
	}
}

func TestApplyFLACEmptiesFlaggedVendor(t *testing.T) {
	out, _, err := run1(t, "b.flac", flacWith("Suno encoder", "TITLE=x"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("Suno")) || !bytes.Contains(out, []byte("TITLE=x")) {
		t.Error("vendor not emptied, or comment lost")
	}
}

func wavWith(chunks ...[]byte) []byte {
	var b bytes.Buffer
	le := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	b.WriteString("RIFF")
	le(uint32(0))
	b.WriteString("WAVEfmt ")
	le(uint32(16))
	b.Write(make([]byte, 16))
	for _, c := range chunks {
		b.Write(c)
	}
	b.WriteString("data")
	le(uint32(8))
	b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	out := b.Bytes()
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)-8))
	return out
}

func riffChunk(id string, body []byte) []byte {
	b := append([]byte(id), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(body)))
	b = append(b, body...)
	if len(body)%2 == 1 {
		b = append(b, 0)
	}
	return b
}

func TestApplyWAVBlanksFlaggedInfoAndBextInPlace(t *testing.T) {
	info := riffChunk("LIST", append([]byte("INFO"), append(riffChunk("ISFT", []byte("Suno\x00")), riffChunk("INAM", []byte("Big Mouf\x00"))...)...))
	bext := make([]byte, 602)
	copy(bext[256:], "ElevenLabs")
	data := wavWith(info, riffChunk("bext", bext))
	out, res, err := run1(t, "a.wav", data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("Suno")) || bytes.Contains(out, []byte("ElevenLabs")) {
		t.Error("flagged values remain")
	}
	if !bytes.Contains(out, []byte("Big Mouf")) {
		t.Error("INAM lost")
	}
	if len(out) != len(data) || !bytes.HasSuffix(out, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Error("sizes or audio changed")
	}
	if len(res.Removed) != 2 {
		t.Errorf("removed %+v", res.Removed)
	}
}
