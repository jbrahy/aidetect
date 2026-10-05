package clean

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/jbrahy/aidetect"
)

// rewritePNG drops whole text chunks (tEXt, iTXt, zTXt) whose keyword and value
// name a generator and whose location is in want. Every other chunk, IDAT
// included, is copied byte for byte, so CRCs stay valid. It returns the
// locations it removed.
func rewritePNG(data []byte, want map[string]bool) ([]byte, map[string]bool, error) {
	if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		return nil, nil, errors.New("not a PNG")
	}
	covered := map[string]bool{}
	out := append([]byte(nil), data[:8]...)
	off := 8
	for off+12 <= len(data) {
		n := int(binary.BigEndian.Uint32(data[off:]))
		if n < 0 || n > len(data)-off-12 {
			break
		}
		typ := string(data[off+4 : off+8])
		chunk := data[off : off+12+n]
		if typ == "tEXt" || typ == "iTXt" || typ == "zTXt" {
			key, val := pngText(typ, data[off+8:off+8+n])
			loc := "PNG " + typ + " " + key
			// An XMP packet is one chunk holding many fields; dropping it would
			// discard everything else in it, so it is left for the caller to handle.
			if want[loc] && !strings.Contains(val, "<x:xmpmeta") && len(aidetect.GeneratorNames(key, val)) > 0 {
				covered[loc] = true
				off += 12 + n
				continue
			}
		}
		out = append(out, chunk...)
		off += 12 + n
		if typ == "IEND" {
			break
		}
	}
	return append(out, data[off:]...), covered, nil
}

// pngText decodes a text chunk the way aidetect does, so the same field is picked.
func pngText(typ string, d []byte) (key, val string) {
	k, rest, _ := bytes.Cut(d, []byte{0})
	key = string(k)
	switch typ {
	case "tEXt":
		r := make([]rune, len(rest))
		for i, c := range rest {
			r[i] = rune(c)
		}
		val = string(r)
	case "iTXt":
		if len(rest) < 2 {
			return
		}
		compressed := rest[0] == 1
		rest = rest[2:]
		_, rest, _ = bytes.Cut(rest, []byte{0})
		_, rest, _ = bytes.Cut(rest, []byte{0})
		if compressed {
			val = inflate(rest)
		} else {
			val = string(rest)
		}
	case "zTXt":
		if len(rest) >= 1 {
			val = inflate(rest[1:])
		}
	}
	return
}

func inflate(b []byte) string {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	defer zr.Close()
	out, _ := io.ReadAll(io.LimitReader(zr, 32<<20))
	return string(out)
}
