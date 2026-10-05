package clean

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/jbrahy/aidetect"
)

// rewriteMP3 removes flagged ID3v2.3/2.4 frames. The tag keeps its declared
// size: removed bytes become padding, so the audio does not move. Tags with
// unsynchronisation, an extended header or a footer, ID3v2.2, ID3v1 and APEv2
// are left alone, which makes their locations unsupported.
func rewriteMP3(data []byte, want map[string]bool) ([]byte, map[string]bool, error) {
	covered := map[string]bool{}
	if len(data) < 10 || !bytes.HasPrefix(data, []byte("ID3")) {
		return data, covered, nil
	}
	ver, flags := data[3], data[5]
	size := int(data[6]&0x7f)<<21 | int(data[7]&0x7f)<<14 | int(data[8]&0x7f)<<7 | int(data[9]&0x7f)
	if (ver != 3 && ver != 4) || flags&0xD0 != 0 || 10+size > len(data) {
		return data, covered, nil
	}
	body := data[10 : 10+size]
	var kept []byte
	pos := 0
	for pos+10 <= len(body) {
		id := string(body[pos : pos+4])
		if body[pos] == 0 || !isFrameID(id) {
			break
		}
		var n int
		if ver == 4 {
			n = int(body[pos+4]&0x7f)<<21 | int(body[pos+5]&0x7f)<<14 | int(body[pos+6]&0x7f)<<7 | int(body[pos+7]&0x7f)
		} else {
			n = int(binary.BigEndian.Uint32(body[pos+4:]))
		}
		if n < 0 || pos+10+n > len(body) {
			break
		}
		frame := body[pos : pos+10+n]
		drop := false
		for _, f := range aidetect.DecodeID3Frame(id, frame[10:]) {
			loc := "ID3v2 " + f.Key
			if want[loc] && len(aidetect.GeneratorNames(f.Key, f.Value)) > 0 {
				covered[loc] = true
				drop = true
			}
		}
		if !drop {
			kept = append(kept, frame...)
		}
		pos += 10 + n
	}
	newBody := append(append(kept, body[pos:]...), make([]byte, size-len(kept)-(len(body)-pos))...)
	out := append([]byte(nil), data[:10]...)
	out = append(out, newBody...)
	return append(out, data[10+size:]...), covered, nil
}

func isFrameID(id string) bool {
	for _, c := range id {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// rewriteFLAC removes flagged Vorbis comment entries and empties a flagged
// vendor string, rewriting that one block with its new length. Other blocks and
// the audio frames are copied verbatim. A leading ID3 tag is not handled.
func rewriteFLAC(data []byte, want map[string]bool) ([]byte, map[string]bool, error) {
	covered := map[string]bool{}
	if !bytes.HasPrefix(data, []byte("fLaC")) {
		return data, covered, nil
	}
	out := append([]byte(nil), data[:4]...)
	off := 4
	for off+4 <= len(data) {
		h := data[off]
		last, typ := h&0x80 != 0, h&0x7f
		n := int(data[off+1])<<16 | int(data[off+2])<<8 | int(data[off+3])
		if off+4+n > len(data) {
			break
		}
		body := data[off+4 : off+4+n]
		if typ == 4 {
			body = rewriteVorbis(body, want, covered)
		}
		hdr := byte(typ)
		if last {
			hdr |= 0x80
		}
		out = append(out, hdr, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
		out = append(out, body...)
		off += 4 + n
		if last {
			break
		}
	}
	return append(out, data[off:]...), covered, nil
}

func rewriteVorbis(d []byte, want, covered map[string]bool) []byte {
	rd := func(b []byte) (string, []byte, bool) {
		if len(b) < 4 {
			return "", b, false
		}
		n := int(binary.LittleEndian.Uint32(b))
		if n < 0 || 4+n > len(b) {
			return "", b, false
		}
		return string(b[4 : 4+n]), b[4+n:], true
	}
	vendor, rest, ok := rd(d)
	if !ok || len(rest) < 4 {
		return d
	}
	count := int(binary.LittleEndian.Uint32(rest))
	rest = rest[4:]
	if want["FLAC VORBIS_COMMENT vendor"] && len(aidetect.GeneratorNames("vendor", vendor)) > 0 {
		covered["FLAC VORBIS_COMMENT vendor"] = true
		vendor = ""
	}
	var entries [][]byte
	for i := 0; i < count; i++ {
		s, next, ok := rd(rest)
		if !ok {
			return d // malformed: leave the block untouched
		}
		k, v, _ := strings.Cut(s, "=")
		key := strings.ToUpper(k)
		loc := "FLAC VORBIS_COMMENT " + key
		if want[loc] && len(aidetect.GeneratorNames(key, v)) > 0 {
			covered[loc] = true
		} else {
			entries = append(entries, rest[:len(rest)-len(next)])
		}
		rest = next
	}
	var out []byte
	out = binary.LittleEndian.AppendUint32(out, uint32(len(vendor)))
	out = append(out, vendor...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(entries)))
	for _, e := range entries {
		out = append(out, e...)
	}
	return append(out, rest...)
}

// rewriteWAV blanks flagged RIFF INFO values and bext Originator/Description
// text with NULs in place. No chunk size changes, so nothing moves.
func rewriteWAV(data []byte, want map[string]bool) ([]byte, map[string]bool, error) {
	covered := map[string]bool{}
	out := append([]byte(nil), data...)
	if len(out) >= 12 {
		walkWAV(out, 12, len(out), "", want, covered, 0)
	}
	return out, covered, nil
}

func walkWAV(b []byte, off, end int, prefix string, want, covered map[string]bool, depth int) {
	for off+8 <= end {
		id := string(b[off : off+4])
		n := int(binary.LittleEndian.Uint32(b[off+4:]))
		body := off + 8
		if n < 0 || body+n > end {
			n = end - body
		}
		switch {
		case id == "LIST" && depth < 4 && n >= 4:
			if string(b[body:body+4]) == "INFO" {
				walkWAV(b, body+4, body+n, "RIFF INFO ", want, covered, depth+1)
			}
		case id == "data":
		case id == "bext" && n >= 256:
			d := b[body : body+n]
			for _, f := range []struct {
				key      string
				from, to int
			}{{"bext:Description", 0, 256}, {"bext:Originator", 256, min(288, n)}} {
				loc := "bext " + f.key
				if want[loc] && len(aidetect.GeneratorNames(f.key, strings.Trim(string(d[f.from:f.to]), "\x00 "))) > 0 {
					clear(d[f.from:f.to])
					covered[loc] = true
				}
			}
		case prefix != "" && isInfoID(id):
			loc := prefix + strings.TrimSpace(id) + " " + id
			if want[loc] && len(aidetect.GeneratorNames(id, strings.TrimRight(string(b[body:body+n]), "\x00"))) > 0 {
				clear(b[body : body+n])
				covered[loc] = true
			}
		}
		off = body + n + n&1
	}
}

func isInfoID(id string) bool { return len(id) == 4 && id[0] == 'I' && isFrameID(id) }
