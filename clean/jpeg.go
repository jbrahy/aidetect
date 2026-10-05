package clean

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jbrahy/aidetect"
)

// rewriteJPEG removes flagged comments, flagged XMP tool fields and flagged EXIF
// ASCII tags. Everything from the start-of-scan marker on is copied verbatim.
// It returns the locations it removed.
func rewriteJPEG(data []byte, want map[string]bool) ([]byte, map[string]bool, error) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, nil, errors.New("not a JPEG")
	}
	covered := map[string]bool{}
	out := append([]byte(nil), data[:2]...)
	off := 2
	for off+4 <= len(data) && data[off] == 0xFF {
		m := data[off+1]
		switch {
		case m == 0xFF: // fill byte
			out = append(out, 0xFF)
			off++
			continue
		case m == 0xD8 || m == 0x01 || (m >= 0xD0 && m <= 0xD7):
			out = append(out, data[off:off+2]...)
			off += 2
			continue
		case m == 0xDA || m == 0xD9:
			return append(out, data[off:]...), covered, nil
		}
		n := int(binary.BigEndian.Uint16(data[off+2:]))
		if n < 2 || off+2+n > len(data) {
			break
		}
		seg := data[off+4 : off+2+n]
		keep, newSeg := true, seg
		if m >= 0xE0 { // APPn and COM
			keep, newSeg = cleanSegment(m, seg, want, covered)
		}
		switch {
		case !keep:
		case bytes.Equal(newSeg, seg):
			out = append(out, data[off:off+2+n]...)
		default:
			out = append(out, 0xFF, m, byte((len(newSeg)+2)>>8), byte(len(newSeg)+2))
			out = append(out, newSeg...)
		}
		off += 2 + n
	}
	return append(out, data[off:]...), covered, nil
}

// cleanSegment returns whether to keep the segment and its (possibly edited) payload.
func cleanSegment(m byte, seg []byte, want, covered map[string]bool) (bool, []byte) {
	switch {
	case m == 0xFE:
		if want["JPEG COM COM"] && len(aidetect.GeneratorNames("COM", string(seg))) > 0 {
			covered["JPEG COM COM"] = true
			return false, nil
		}
		return true, seg
	case m == 0xE1 && bytes.HasPrefix(seg, []byte("Exif\x00\x00")):
		return true, append([]byte("Exif\x00\x00"), blankEXIF(seg[6:], want, covered)...)
	}
	return true, cleanXMP(seg, fmt.Sprintf("JPEG APP%d", m-0xE0), m, want, covered)
}

var exifNames = map[uint16]string{0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model",
	0x0131: "Software", 0x013B: "Artist", 0x8298: "Copyright", 0x9286: "UserComment"}

// blankEXIF overwrites flagged ASCII IFD0 values with NULs. The IFD is not
// restructured, so no offset moves. aidetect reads a blanked value as empty.
func blankEXIF(t []byte, want, covered map[string]bool) []byte {
	out := append([]byte(nil), t...)
	if len(out) < 8 {
		return out
	}
	var bo binary.ByteOrder
	switch string(out[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return out
	}
	ifd := int(bo.Uint32(out[4:8]))
	if ifd < 0 || ifd+2 > len(out) {
		return out
	}
	cnt := int(bo.Uint16(out[ifd:]))
	for i := 0; i < cnt; i++ {
		e := ifd + 2 + i*12
		if e+12 > len(out) {
			break
		}
		tag, typ := bo.Uint16(out[e:]), bo.Uint16(out[e+2:])
		n := int(bo.Uint32(out[e+4:]))
		name, ok := exifNames[tag]
		if !ok || typ != 2 || n <= 0 || !want["EXIF "+name] {
			continue
		}
		p := e + 8
		if n > 4 {
			p = int(bo.Uint32(out[e+8:]))
		}
		if p < 0 || p+n > len(out) {
			continue
		}
		if len(aidetect.GeneratorNames(name, strings.TrimRight(string(out[p:p+n]), "\x00 "))) > 0 {
			for j := p; j < p+n; j++ {
				out[j] = 0
			}
			covered["EXIF "+name] = true
		}
	}
	return out
}

var (
	xmpAttrRe = regexp.MustCompile(`\s+[A-Za-z][\w.-]*:(CreatorTool|softwareAgent)\s*=\s*"([^"]*)"`)
	xmpOpenRe = regexp.MustCompile(`<([A-Za-z][\w.-]*):(CreatorTool|softwareAgent)(?:\s[^>]*)?>`)
	xmpAltRe  = regexp.MustCompile(`^\s*(?:<rdf:Alt>\s*<rdf:li[^>]*>)?([^<]*)`)
)

// cleanXMP removes flagged CreatorTool and softwareAgent attributes and
// elements from any XMP packet in the segment.
func cleanXMP(seg []byte, region string, m byte, want, covered map[string]bool) []byte {
	if !bytes.Contains(seg, []byte("<x:xmpmeta")) {
		return seg
	}
	if m == 0xFE {
		return seg
	}
	type span struct{ a, b int }
	var cut []span
	flagged := func(name, val, loc string) bool {
		if want[loc] && len(aidetect.GeneratorNames("XMP:"+name, strings.TrimSpace(val))) > 0 {
			covered[loc] = true
			return true
		}
		return false
	}
	for _, ix := range xmpAttrRe.FindAllSubmatchIndex(seg, -1) {
		name, val := string(seg[ix[2]:ix[3]]), string(seg[ix[4]:ix[5]])
		if flagged(name, val, region+" XMP:"+name) {
			cut = append(cut, span{ix[0], ix[1]})
		}
	}
	for _, ix := range xmpOpenRe.FindAllSubmatchIndex(seg, -1) {
		prefix, name := string(seg[ix[2]:ix[3]]), string(seg[ix[4]:ix[5]])
		if seg[ix[1]-2] == '/' {
			continue // self-closing, no value
		}
		closeTag := []byte("</" + prefix + ":" + name + ">")
		j := bytes.Index(seg[ix[1]:], closeTag)
		if j < 0 {
			continue
		}
		inner := seg[ix[1] : ix[1]+j]
		val := ""
		if mm := xmpAltRe.FindSubmatch(inner); mm != nil {
			val = string(mm[1])
		}
		if flagged(name, val, region+" XMP:"+name) {
			cut = append(cut, span{ix[0], ix[1] + j + len(closeTag)})
		}
	}
	if len(cut) == 0 {
		return seg
	}
	sort.Slice(cut, func(i, j int) bool { return cut[i].a < cut[j].a })
	var out []byte
	pos := 0
	for _, c := range cut {
		if c.a < pos {
			continue
		}
		out = append(out, seg[pos:c.a]...)
		pos = c.b
	}
	return append(out, seg[pos:]...)
}
