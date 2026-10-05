package aidetect

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Region is a slice of a file that can carry metadata (never the encoded
// essence: no mdat, IDAT, audio "data", etc.). Fields holds whatever key/value
// pairs the container parser could decode structurally; Data is the raw bytes,
// which the string/XMP/C2PA analyzers scan.
type Region struct {
	Name   string
	Data   []byte
	Fields []Field
}

type Field struct {
	Key   string
	Value string
}

const (
	maxRegion   = 32 << 20 // cap on any single metadata region we pull into memory
	genericHead = 1 << 20
	genericTail = 256 << 10
)

// extract sniffs the container and returns its metadata regions.
func extract(r io.ReaderAt, size int64) (format string, regions []Region, err error) {
	head, err := readAt(r, 0, min64(size, 64))
	if err != nil {
		return "", nil, err
	}
	switch {
	case bytes.HasPrefix(head, []byte("ID3")):
		return extractID3Prefixed(r, size)
	case bytes.HasPrefix(head, []byte("fLaC")):
		regions, err = extractFLAC(r, size, 0)
		return "flac", regions, err
	case len(head) >= 12 && (bytes.HasPrefix(head, []byte("RIFF")) || bytes.HasPrefix(head, []byte("RF64"))):
		form := strings.ToLower(strings.TrimSpace(string(head[8:12])))
		regions, err = extractRIFF(r, size)
		return form, regions, err
	case len(head) >= 12 && bytes.HasPrefix(head, []byte("FORM")):
		regions, err = extractAIFF(r, size)
		return strings.ToLower(string(head[8:12])), regions, err
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		regions, err = extractPNG(r, size)
		return "png", regions, err
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF}):
		regions, err = extractJPEG(r, size)
		return "jpeg", regions, err
	case len(head) >= 8 && isISOBMFF(head[4:8]):
		regions, err = extractMP4(r, size)
		return "isobmff", regions, err
	}
	format = "unknown"
	switch {
	case bytes.HasPrefix(head, []byte("OggS")):
		format = "ogg"
	case bytes.HasPrefix(head, []byte{0x1A, 0x45, 0xDF, 0xA3}):
		format = "matroska"
	case bytes.HasPrefix(head, []byte("GIF8")):
		format = "gif"
	case len(head) >= 2 && head[0] == 0xFF && head[1]&0xE0 == 0xE0:
		format = "mpeg-audio"
	}
	regions, err = extractGeneric(r, size)
	if format == "mpeg-audio" {
		regions = append(regions, tailTags(r, size)...)
	}
	return format, regions, err
}

func isISOBMFF(t []byte) bool {
	switch string(t) {
	case "ftyp", "moov", "mdat", "wide", "free", "skip", "uuid":
		return true
	}
	return false
}

func readAt(r io.ReaderAt, off, n int64) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative read at %d", off)
	}
	b := make([]byte, n)
	got, err := r.ReadAt(b, off)
	if err == io.EOF && int64(got) == n {
		err = nil
	}
	if err == io.EOF {
		return b[:got], nil
	}
	return b[:got], err
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func extractGeneric(r io.ReaderAt, size int64) ([]Region, error) {
	h, err := readAt(r, 0, min64(size, genericHead))
	if err != nil {
		return nil, err
	}
	regions := []Region{{Name: "head", Data: h}}
	if size > genericHead {
		start := size - genericTail
		if start < genericHead {
			start = genericHead
		}
		t, err := readAt(r, start, size-start)
		if err != nil {
			return nil, err
		}
		regions = append(regions, Region{Name: "tail", Data: t})
	}
	return regions, nil
}

// ---------- ID3v2 / MP3 ----------

func extractID3Prefixed(r io.ReaderAt, size int64) (string, []Region, error) {
	hdr, err := readAt(r, 0, 10)
	if err != nil || len(hdr) < 10 {
		return "mp3", nil, fmt.Errorf("short ID3 header")
	}
	tagLen := int64(syncsafe(hdr[6:10])) + 10
	if hdr[5]&0x10 != 0 { // footer present
		tagLen += 10
	}
	tag, err := readAt(r, 0, min64(min64(tagLen, size), maxRegion))
	if err != nil {
		return "mp3", nil, err
	}
	regions := []Region{{Name: "ID3v2", Data: tag, Fields: parseID3v2(tag)}}

	// ID3 is sometimes prepended to FLAC/AAC; keep going if we recognise what follows.
	next, _ := readAt(r, tagLen, 4)
	if bytes.Equal(next, []byte("fLaC")) {
		more, err := extractFLAC(r, size, tagLen)
		return "flac", append(regions, more...), err
	}
	regions = append(regions, tailTags(r, size)...)
	return "mp3", regions, nil
}

func syncsafe(b []byte) uint32 {
	return uint32(b[0]&0x7f)<<21 | uint32(b[1]&0x7f)<<14 | uint32(b[2]&0x7f)<<7 | uint32(b[3]&0x7f)
}

func parseID3v2(tag []byte) []Field {
	if len(tag) < 10 {
		return nil
	}
	ver := tag[3]
	flags := tag[5]
	body := tag[10:]
	if flags&0x80 != 0 && ver < 4 { // whole-tag unsynchronisation (v2.2/2.3)
		body = bytes.ReplaceAll(body, []byte{0xFF, 0x00}, []byte{0xFF})
	}
	if flags&0x40 != 0 && len(body) >= 4 { // extended header
		var n int
		if ver >= 4 {
			n = int(syncsafe(body[:4]))
		} else {
			n = int(binary.BigEndian.Uint32(body[:4])) + 4
		}
		if n > len(body) {
			return nil
		}
		body = body[n:]
	}
	idLen, hdrLen := 4, 10
	if ver == 2 {
		idLen, hdrLen = 3, 6
	}
	var out []Field
	for len(body) >= hdrLen {
		id := string(body[:idLen])
		if body[0] == 0 || !isFrameID(id) {
			break // padding or garbage
		}
		var n int
		switch ver {
		case 2:
			n = int(body[3])<<16 | int(body[4])<<8 | int(body[5])
		case 3:
			n = int(binary.BigEndian.Uint32(body[4:8]))
		default:
			n = int(syncsafe(body[4:8]))
		}
		if n < 0 || hdrLen+n > len(body) {
			break
		}
		data := body[hdrLen : hdrLen+n]
		body = body[hdrLen+n:]
		out = append(out, decodeID3Frame(id, data)...)
	}
	return out
}

func isFrameID(id string) bool {
	for _, c := range id {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func decodeID3Frame(id string, data []byte) []Field {
	switch {
	case id == "TXXX" || id == "TXX":
		if len(data) < 1 {
			return nil
		}
		parts := splitEncoded(data[0], data[1:], 2)
		if len(parts) == 2 {
			return []Field{{Key: "TXXX:" + parts[0], Value: parts[1]}}
		}
	case id == "COMM" || id == "COM" || id == "USLT" || id == "ULT":
		if len(data) < 4 {
			return nil
		}
		parts := splitEncoded(data[0], data[4:], 2)
		if len(parts) == 2 {
			k := id
			if parts[0] != "" {
				k += ":" + parts[0]
			}
			return []Field{{Key: k, Value: parts[1]}}
		}
	case id == "WXXX" || id == "WXX":
		if len(data) < 1 {
			return nil
		}
		desc := splitEncoded(data[0], data[1:], 2)
		url := latin1(bytes.TrimRight(encodedRest(data[0], data[1:]), "\x00"))
		return []Field{{Key: "WXXX:" + desc[0], Value: url}}
	case id == "PRIV":
		if i := bytes.IndexByte(data, 0); i > 0 {
			return []Field{{Key: "PRIV:" + string(data[:i]), Value: printable(data[i+1:])}}
		}
	case id[0] == 'T':
		if len(data) < 1 {
			return nil
		}
		return []Field{{Key: id, Value: strings.Join(splitEncoded(data[0], data[1:], -1), " / ")}}
	case id[0] == 'W':
		return []Field{{Key: id, Value: latin1(bytes.TrimRight(data, "\x00"))}}
	}
	return nil
}

// encodedRest returns the bytes after the first terminator (used for WXXX URL).
func encodedRest(enc byte, b []byte) []byte {
	term := []byte{0}
	if enc == 1 || enc == 2 {
		term = []byte{0, 0}
	}
	for i := 0; i+len(term) <= len(b); i += len(term) {
		if bytes.Equal(b[i:i+len(term)], term) {
			return b[i+len(term):]
		}
	}
	return nil
}

// splitEncoded splits an ID3 string list on the encoding-appropriate terminator.
func splitEncoded(enc byte, b []byte, n int) []string {
	var raw [][]byte
	if enc == 1 || enc == 2 {
		for len(b) >= 2 && (n < 0 || len(raw) < n-1) {
			i := 0
			for ; i+1 < len(b); i += 2 {
				if b[i] == 0 && b[i+1] == 0 {
					break
				}
			}
			if i+1 >= len(b) {
				break
			}
			raw = append(raw, b[:i])
			b = b[i+2:]
		}
		raw = append(raw, b)
	} else if n < 0 {
		raw = bytes.Split(b, []byte{0})
	} else {
		raw = bytes.SplitN(b, []byte{0}, n)
	}
	var out []string
	for _, s := range raw {
		out = append(out, decodeText(enc, s))
	}
	for len(out) > 1 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

func decodeText(enc byte, b []byte) string {
	switch enc {
	case 1, 2:
		bigEndian := enc == 2
		if len(b) >= 2 {
			if b[0] == 0xFF && b[1] == 0xFE {
				bigEndian, b = false, b[2:]
			} else if b[0] == 0xFE && b[1] == 0xFF {
				bigEndian, b = true, b[2:]
			}
		}
		var sb strings.Builder
		for i := 0; i+1 < len(b); i += 2 {
			var u uint16
			if bigEndian {
				u = uint16(b[i])<<8 | uint16(b[i+1])
			} else {
				u = uint16(b[i+1])<<8 | uint16(b[i])
			}
			if u == 0 {
				break
			}
			sb.WriteRune(rune(u)) // surrogate pairs are irrelevant for tool names
		}
		return sb.String()
	case 3:
		return strings.TrimRight(string(b), "\x00")
	default:
		return latin1(bytes.TrimRight(b, "\x00"))
	}
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
		if sb.Len() > 200 {
			break
		}
	}
	return sb.String()
}

// tailTags reads ID3v1 and APEv2 footers.
func tailTags(r io.ReaderAt, size int64) []Region {
	var out []Region
	if size >= 128 {
		t, _ := readAt(r, size-128, 128)
		if bytes.HasPrefix(t, []byte("TAG")) {
			f := []Field{
				{"ID3v1:title", trimTag(t[3:33])},
				{"ID3v1:artist", trimTag(t[33:63])},
				{"ID3v1:album", trimTag(t[63:93])},
				{"ID3v1:comment", trimTag(t[97:127])},
			}
			out = append(out, Region{Name: "ID3v1", Data: t, Fields: f})
		}
	}
	// APEv2: footer "APETAGEX" 32 bytes before end (or before ID3v1).
	for _, back := range []int64{32, 160} {
		if size < back {
			continue
		}
		f, _ := readAt(r, size-back, 32)
		if len(f) == 32 && bytes.HasPrefix(f, []byte("APETAGEX")) {
			n := int64(binary.LittleEndian.Uint32(f[12:16]))
			start := size - back + 32 - n
			if start >= 0 && n <= maxRegion {
				d, _ := readAt(r, start, n)
				out = append(out, Region{Name: "APEv2", Data: d})
			}
		}
	}
	return out
}

func trimTag(b []byte) string {
	return strings.TrimSpace(latin1(bytes.TrimRight(b, "\x00 ")))
}

// ---------- FLAC ----------

func extractFLAC(r io.ReaderAt, size, off int64) ([]Region, error) {
	off += 4
	var out []Region
	for off+4 <= size {
		h, err := readAt(r, off, 4)
		if err != nil || len(h) < 4 {
			return out, err
		}
		last := h[0]&0x80 != 0
		typ := h[0] & 0x7f
		n := int64(h[1])<<16 | int64(h[2])<<8 | int64(h[3])
		off += 4
		switch typ {
		case 2, 4, 6: // APPLICATION, VORBIS_COMMENT, PICTURE
			d, err := readAt(r, off, min64(n, maxRegion))
			if err != nil {
				return out, err
			}
			reg := Region{Name: fmt.Sprintf("FLAC block %d", typ), Data: d}
			if typ == 4 {
				reg.Name = "FLAC VORBIS_COMMENT"
				reg.Fields = parseVorbisComment(d)
			}
			if typ == 6 {
				// Embedded cover art: scan only its first 64 KiB for XMP/C2PA/EXIF.
				if len(reg.Data) > 64<<10 {
					reg.Data = reg.Data[:64<<10]
				}
				reg.Name = "FLAC PICTURE"
			}
			out = append(out, reg)
		}
		off += n
		if last {
			break
		}
	}
	return out, nil
}

// parseVorbisComment decodes the (little-endian, length-prefixed) Vorbis
// comment layout used by FLAC, Ogg Vorbis and Opus.
func parseVorbisComment(d []byte) []Field {
	rd := func() (string, bool) {
		if len(d) < 4 {
			return "", false
		}
		n := int(binary.LittleEndian.Uint32(d[:4]))
		if n < 0 || 4+n > len(d) {
			return "", false
		}
		s := string(d[4 : 4+n])
		d = d[4+n:]
		return s, true
	}
	vendor, ok := rd()
	if !ok {
		return nil
	}
	out := []Field{{Key: "vendor", Value: vendor}}
	if len(d) < 4 {
		return out
	}
	count := int(binary.LittleEndian.Uint32(d[:4]))
	d = d[4:]
	for i := 0; i < count; i++ {
		s, ok := rd()
		if !ok {
			break
		}
		k, v, _ := strings.Cut(s, "=")
		out = append(out, Field{Key: strings.ToUpper(k), Value: v})
	}
	return out
}

// ---------- RIFF (WAV / WebP / AVI) and AIFF ----------

var riffEssence = map[string]bool{"data": true, "VP8 ": true, "VP8L": true, "ALPH": true, "ANMF": true, "idx1": true}

func extractRIFF(r io.ReaderAt, size int64) ([]Region, error) {
	var out []Region
	err := walkRIFF(r, 12, size, binary.LittleEndian, &out, 0)
	return out, err
}

func walkRIFF(r io.ReaderAt, off, end int64, bo binary.ByteOrder, out *[]Region, depth int) error {
	for off+8 <= end {
		h, err := readAt(r, off, 8)
		if err != nil || len(h) < 8 {
			return err
		}
		id := string(h[:4])
		n := int64(bo.Uint32(h[4:8]))
		body := off + 8
		if n == 0xFFFFFFFF || body+n > end { // RF64 / truncated
			n = end - body
		}
		switch {
		case id == "LIST" && depth < 4 && n >= 4:
			lt, _ := readAt(r, body, 4)
			if string(lt) == "movi" {
				break // AVI essence
			}
			sub := len(*out)
			if err := walkRIFF(r, body+4, body+n, bo, out, depth+1); err != nil {
				return err
			}
			if string(lt) == "INFO" {
				for i := sub; i < len(*out); i++ {
					(*out)[i].Name = "RIFF INFO " + (*out)[i].Name
				}
			}
		case riffEssence[id]:
		default:
			d, err := readAt(r, body, min64(n, maxRegion))
			if err != nil {
				return err
			}
			reg := Region{Name: strings.TrimSpace(id), Data: d}
			if isInfoID(id) {
				reg.Fields = []Field{{Key: id, Value: strings.TrimRight(string(d), "\x00")}}
			}
			if id == "bext" && len(d) >= 256 {
				reg.Fields = []Field{
					{Key: "bext:Description", Value: trimTag(d[:256])},
					{Key: "bext:Originator", Value: trimTag(d[256:min(288, len(d))])},
				}
			}
			*out = append(*out, reg)
		}
		off = body + n + n&1
	}
	return nil
}

func isInfoID(id string) bool {
	return len(id) == 4 && id[0] == 'I' && isFrameID(id)
}

func extractAIFF(r io.ReaderAt, size int64) ([]Region, error) {
	var out []Region
	off := int64(12)
	for off+8 <= size {
		h, err := readAt(r, off, 8)
		if err != nil || len(h) < 8 {
			return out, err
		}
		id := string(h[:4])
		n := int64(binary.BigEndian.Uint32(h[4:8]))
		body := off + 8
		if id != "SSND" {
			d, err := readAt(r, body, min64(n, maxRegion))
			if err != nil {
				return out, err
			}
			reg := Region{Name: "AIFF " + strings.TrimSpace(id), Data: d}
			switch id {
			case "NAME", "AUTH", "ANNO", "(c) ":
				reg.Fields = []Field{{Key: id, Value: strings.TrimRight(string(d), "\x00")}}
			case "ID3 ", "id3 ":
				reg.Fields = parseID3v2(d)
			}
			out = append(out, reg)
		}
		off = body + n + n&1
	}
	return out, nil
}

// ---------- PNG ----------

func extractPNG(r io.ReaderAt, size int64) ([]Region, error) {
	var out []Region
	off := int64(8)
	for off+8 <= size {
		h, err := readAt(r, off, 8)
		if err != nil || len(h) < 8 {
			return out, err
		}
		n := int64(binary.BigEndian.Uint32(h[:4]))
		typ := string(h[4:8])
		if typ != "IDAT" && typ != "fdAT" {
			d, err := readAt(r, off+8, min64(n, maxRegion))
			if err != nil {
				return out, err
			}
			reg := Region{Name: "PNG " + typ, Data: d}
			switch typ {
			case "tEXt":
				k, v, _ := bytes.Cut(d, []byte{0})
				reg.Fields = []Field{{Key: string(k), Value: latin1(v)}}
			case "iTXt":
				// keyword\0 compflag compmethod lang\0 translated\0 text
				k, rest, _ := bytes.Cut(d, []byte{0})
				if len(rest) >= 2 {
					text := skipITXtHeader(rest)
					v := string(text)
					if rest[0] == 1 {
						v = inflateOrEmpty(text)
					}
					reg.Fields = []Field{{Key: string(k), Value: v}}
				}
			case "zTXt":
				k, rest, _ := bytes.Cut(d, []byte{0})
				if len(rest) >= 1 {
					reg.Fields = []Field{{Key: string(k), Value: inflateOrEmpty(rest[1:])}}
				}
			}
			out = append(out, reg)
		}
		if typ == "IEND" {
			break
		}
		off += 12 + n
	}
	return out, nil
}

func skipITXtHeader(rest []byte) []byte {
	rest = rest[2:]
	_, rest, _ = bytes.Cut(rest, []byte{0})
	_, rest, _ = bytes.Cut(rest, []byte{0})
	return rest
}

// ---------- JPEG ----------

func extractJPEG(r io.ReaderAt, size int64) ([]Region, error) {
	var out []Region
	off := int64(2)
	for off+4 <= size {
		h, err := readAt(r, off, 4)
		if err != nil || len(h) < 4 {
			return out, err
		}
		if h[0] != 0xFF {
			break
		}
		m := h[1]
		if m == 0xD8 || m == 0x01 || (m >= 0xD0 && m <= 0xD7) || m == 0xFF {
			off += 2
			if m == 0xFF {
				off--
			}
			continue
		}
		if m == 0xDA || m == 0xD9 { // SOS: entropy-coded data follows
			break
		}
		n := int64(binary.BigEndian.Uint16(h[2:4]))
		if m >= 0xE0 || m == 0xFE { // APPn, COM
			d, err := readAt(r, off+4, min64(n-2, maxRegion))
			if err != nil {
				return out, err
			}
			reg := Region{Name: fmt.Sprintf("JPEG APP%d", m-0xE0), Data: d}
			if m == 0xFE {
				reg.Name = "JPEG COM"
				reg.Fields = []Field{{Key: "COM", Value: string(d)}}
			}
			if m == 0xE1 && bytes.HasPrefix(d, []byte("Exif\x00\x00")) {
				reg.Name = "EXIF"
				reg.Fields = parseEXIF(d[6:])
			}
			out = append(out, reg)
		}
		off += 2 + n
	}
	return out, nil
}

// parseEXIF pulls the handful of ASCII IFD0 tags that name the producing tool.
func parseEXIF(t []byte) []Field {
	if len(t) < 8 {
		return nil
	}
	var bo binary.ByteOrder
	switch string(t[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return nil
	}
	names := map[uint16]string{0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model",
		0x0131: "Software", 0x013B: "Artist", 0x8298: "Copyright", 0x9286: "UserComment"}
	ifd := int(bo.Uint32(t[4:8]))
	if ifd+2 > len(t) {
		return nil
	}
	var out []Field
	cnt := int(bo.Uint16(t[ifd:]))
	for i := 0; i < cnt; i++ {
		e := ifd + 2 + i*12
		if e+12 > len(t) {
			break
		}
		tag, typ := bo.Uint16(t[e:]), bo.Uint16(t[e+2:])
		n := int(bo.Uint32(t[e+4:]))
		name, ok := names[tag]
		if !ok || typ != 2 || n <= 0 {
			continue
		}
		var v []byte
		if n <= 4 {
			v = t[e+8 : e+8+n]
		} else {
			p := int(bo.Uint32(t[e+8:]))
			if p < 0 || p+n > len(t) {
				continue
			}
			v = t[p : p+n]
		}
		out = append(out, Field{Key: name, Value: strings.TrimRight(string(v), "\x00 ")})
	}
	return out
}

// ---------- ISO BMFF (MP4 / MOV / M4A / HEIC / AVIF) ----------

var bmffContainers = map[string]bool{"moov": true, "udta": true, "trak": true, "mdia": true, "minf": true, "ilst": true, "meta": true}

func extractMP4(r io.ReaderAt, size int64) ([]Region, error) {
	var out []Region
	off := int64(0)
	for off+8 <= size {
		typ, hdr, n, err := bmffHeader(r, off, size)
		if err != nil {
			return out, err
		}
		if typ != "mdat" && typ != "free" && typ != "skip" && typ != "wide" {
			d, err := readAt(r, off+hdr, min64(n-hdr, maxRegion))
			if err != nil {
				return out, err
			}
			reg := Region{Name: "MP4 " + typ, Data: d}
			if typ == "moov" || typ == "meta" {
				reg.Fields = bmffFields(d, typ, 0)
			}
			out = append(out, reg)
		}
		if n <= 0 {
			break
		}
		off += n
	}
	return out, nil
}

func bmffHeader(r io.ReaderAt, off, end int64) (typ string, hdr, n int64, err error) {
	h, err := readAt(r, off, 16)
	if err != nil || len(h) < 8 {
		return "", 0, 0, fmt.Errorf("short box header at %d", off)
	}
	n = int64(binary.BigEndian.Uint32(h[:4]))
	typ = string(h[4:8])
	hdr = 8
	switch n {
	case 0:
		n = end - off
	case 1:
		if len(h) < 16 {
			return "", 0, 0, fmt.Errorf("short largesize box at %d", off)
		}
		n = int64(binary.BigEndian.Uint64(h[8:16]))
		hdr = 16
	}
	if n < hdr || off+n > end {
		n = end - off
	}
	return typ, hdr, n, nil
}

// bmffFields walks an in-memory box tree for iTunes-style ilst items and
// QuickTime ©xxx user-data strings.
func bmffFields(d []byte, parent string, depth int) []Field {
	if depth > 8 {
		return nil
	}
	if parent == "meta" && len(d) >= 12 && string(d[8:12]) == "hdlr" {
		d = d[4:] // ISO meta is a full box (version/flags); QuickTime meta is not
	}
	var out []Field
	for len(d) >= 8 {
		n := int(binary.BigEndian.Uint32(d[:4]))
		typ := string(d[4:8])
		if n < 8 || n > len(d) {
			break
		}
		body := d[8:n]
		switch {
		case bmffContainers[typ]:
			out = append(out, bmffFields(body, typ, depth+1)...)
		case parent == "ilst":
			out = append(out, ilstItem(typ, body)...)
		case parent == "udta" && len(typ) == 4 && typ[0] == 0xA9 && len(body) > 4:
			// QuickTime ©xxx: 2-byte length, 2-byte language, text
			l := int(binary.BigEndian.Uint16(body[:2]))
			if 4+l <= len(body) {
				out = append(out, Field{Key: "©" + typ[1:], Value: string(body[4 : 4+l])})
			}
		}
		d = d[n:]
	}
	return out
}

func ilstItem(typ string, body []byte) []Field {
	key := typ
	if typ[0] == 0xA9 {
		key = "©" + typ[1:]
	}
	var out []Field
	for len(body) >= 8 {
		n := int(binary.BigEndian.Uint32(body[:4]))
		t := string(body[4:8])
		if n < 8 || n > len(body) {
			break
		}
		b := body[8:n]
		switch t {
		case "name":
			if len(b) > 4 {
				key = "----:" + string(b[4:])
			}
		case "data":
			if len(b) > 8 && binary.BigEndian.Uint32(b[:4])&0xFFFFFF == 1 { // UTF-8
				out = append(out, Field{Key: key, Value: string(b[8:])})
			}
		}
		body = body[n:]
	}
	return out
}

func inflateOrEmpty(b []byte) string {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	defer zr.Close()
	out, _ := io.ReadAll(io.LimitReader(zr, maxRegion))
	return string(out)
}

// DecodeID3Frame decodes the body of one ID3v2 frame into the key/value fields
// Inspect reports for it, so tools that rewrite tags pick the same fields.
func DecodeID3Frame(id string, data []byte) []Field {
	if len(id) < 3 {
		return nil
	}
	return decodeID3Frame(id, data)
}
