package aidetect

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Severity int

const (
	SevInfo Severity = iota
	SevWeak
	SevStrong
)

func (s Severity) String() string {
	return [...]string{"info", "weak", "strong"}[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

type Finding struct {
	Source   string   `json:"source"` // metadata | xmp | c2pa | strings | spectral | remote:<name>
	Severity Severity `json:"severity"`
	Location string   `json:"location"`
	Detail   string   `json:"detail"`
	key      string
}

// analyzeRegions runs every metadata analyzer and returns de-duplicated findings.
func analyzeRegions(regions []Region) []Finding {
	var fs []Finding
	for _, reg := range regions {
		fields := reg.Fields
		fields = append(fields, xmpFields(reg.Data)...)
		c2paFs, c2paFields := analyzeC2PA(reg)
		fs = append(fs, c2paFs...)
		fields = append(fields, c2paFields...)
		fs = append(fs, analyzeFields(reg.Name, fields)...)
		fs = append(fs, analyzeDigitalSourceType(reg)...)
		fs = append(fs, analyzeStrings(reg)...)
	}
	return dedupe(fs)
}

func analyzeFields(region string, fields []Field) []Finding {
	var fs []Finding
	for _, f := range fields {
		if strings.TrimSpace(f.Value) == "" {
			continue
		}
		loc := region + " " + f.Key
		for _, sg := range matchSignatures(f.Value, isToolKey(f.Key)) {
			fs = append(fs, Finding{Source: "metadata", Severity: sg.Severity, Location: loc,
				Detail: fmt.Sprintf("%s: %q", sg.Name, clip(f.Value, 160)), key: "sig:" + sg.Name})
		}
		fs = append(fs, generatorParams(loc, f)...)
	}
	return fs
}

var a1111Re = regexp.MustCompile(`(?s)Steps:\s*\d+.*(Sampler|CFG scale|Seed):`)

// generatorParams catches the parameter dumps that local diffusion front-ends
// write into PNG text chunks even when no tool name is present.
func generatorParams(loc string, f Field) []Finding {
	k := strings.ToLower(f.Key)
	mk := func(what string) []Finding {
		return []Finding{{Source: "metadata", Severity: SevStrong, Location: loc,
			Detail: what + ": " + clip(f.Value, 160), key: "params:" + what}}
	}
	switch {
	case k == "parameters" && a1111Re.MatchString(f.Value):
		return mk("Stable Diffusion WebUI generation parameters")
	case (k == "prompt" || k == "workflow") && strings.Contains(f.Value, `"class_type"`) || k == "workflow" && strings.Contains(f.Value, `"nodes"`):
		return mk("ComfyUI workflow graph")
	case k == "invokeai_metadata" || k == "sd-metadata" || k == "dream":
		return mk("InvokeAI generation metadata")
	case k == "aisystemused" || k == "aipromptinformation" || k == "aisystemversionused" || k == "aipromptwritername":
		return mk("IPTC AI disclosure (" + f.Key + ")")
	}
	return nil
}

// ---------- XMP ----------

var (
	xmpToolRe = regexp.MustCompile(`(?i)(CreatorTool|softwareAgent|AISystemUsed|AISystemVersionUsed|AIPromptInformation|AIPromptWriterName)(?:\s*=\s*"([^"]*)"|>\s*(?:<rdf:Alt>\s*<rdf:li[^>]*>)?([^<]+)<)`)
)

func xmpPackets(b []byte) [][]byte {
	var out [][]byte
	for {
		i := bytes.Index(b, []byte("<x:xmpmeta"))
		if i < 0 {
			return out
		}
		j := bytes.Index(b[i:], []byte("</x:xmpmeta>"))
		if j < 0 {
			return append(out, b[i:])
		}
		out = append(out, b[i:i+j+12])
		b = b[i+j+12:]
	}
}

func xmpFields(b []byte) []Field {
	var out []Field
	for _, p := range xmpPackets(b) {
		for _, m := range xmpToolRe.FindAllSubmatch(p, -1) {
			v := string(m[2])
			if v == "" {
				v = string(m[3])
			}
			out = append(out, Field{Key: "XMP:" + string(m[1]), Value: strings.TrimSpace(v)})
		}
	}
	return out
}

// ---------- IPTC digital source type (XMP or C2PA) ----------

var dstRe = regexp.MustCompile(`(?i)digitalsourcetype/([a-z]+)`)

func analyzeDigitalSourceType(reg Region) []Finding {
	var fs []Finding
	for _, m := range dstRe.FindAllSubmatch(reg.Data, -1) {
		v := strings.ToLower(string(m[1]))
		d, ok := digitalSourceTypes[v]
		if !ok {
			d.Sev, d.Desc = SevInfo, "unrecognised source type"
		}
		src := "xmp"
		if isC2PA(reg.Data) {
			src = "c2pa"
		}
		fs = append(fs, Finding{Source: src, Severity: d.Sev, Location: reg.Name,
			Detail: fmt.Sprintf("IPTC DigitalSourceType %s: %s", m[1], d.Desc), key: "dst:" + v})
	}
	return fs
}

// ---------- C2PA / Content Credentials ----------

func isC2PA(b []byte) bool {
	return bytes.Contains(b, []byte("jumb")) && bytes.Contains(b, []byte("c2pa"))
}

func analyzeC2PA(reg Region) ([]Finding, []Field) {
	if !isC2PA(reg.Data) {
		return nil, nil
	}
	fs := []Finding{{Source: "c2pa", Severity: SevInfo, Location: reg.Name,
		Detail: "C2PA manifest present (signature NOT validated here; use c2patool to verify)", key: "c2pa:present"}}
	var fields []Field
	for _, k := range []string{"claim_generator", "softwareAgent"} {
		for _, v := range cborTextsAfterKey(reg.Data, k) {
			fields = append(fields, Field{Key: k, Value: v})
		}
	}
	if bytes.Contains(reg.Data, []byte("c2pa.created")) {
		fs = append(fs, Finding{Source: "c2pa", Severity: SevInfo, Location: reg.Name,
			Detail: "manifest records a c2pa.created action", key: "c2pa:created"})
	}
	return fs, fields
}

// cborTextsAfterKey finds a CBOR text-string map key and returns the text
// value that follows it. If the value is itself a map (C2PA v2 softwareAgent
// / claim_generator_info), it returns that map's "name" entry.
func cborTextsAfterKey(b []byte, key string) []string {
	enc := cborText(key)
	var out []string
	for off := 0; ; {
		i := bytes.Index(b[off:], enc)
		if i < 0 {
			return out
		}
		p := off + i + len(enc)
		off = p
		if p >= len(b) {
			return out
		}
		if b[p]&0xE0 == 0xA0 { // map: look for its "name"
			name := cborText("name")
			end := min(len(b), p+256)
			if j := bytes.Index(b[p:end], name); j >= 0 {
				p += j + len(name)
			} else {
				continue
			}
		}
		if s, ok := readCBORText(b[p:]); ok {
			out = append(out, s)
		}
	}
}

func cborText(s string) []byte {
	n := len(s)
	switch {
	case n < 24:
		return append([]byte{0x60 | byte(n)}, s...)
	case n < 256:
		return append([]byte{0x78, byte(n)}, s...)
	default:
		return append([]byte{0x79, byte(n >> 8), byte(n)}, s...)
	}
}

func readCBORText(b []byte) (string, bool) {
	if len(b) == 0 || b[0]&0xE0 != 0x60 {
		return "", false
	}
	ai := int(b[0] & 0x1F)
	var n, h int
	switch {
	case ai < 24:
		n, h = ai, 1
	case ai == 24 && len(b) >= 2:
		n, h = int(b[1]), 2
	case ai == 25 && len(b) >= 3:
		n, h = int(binary.BigEndian.Uint16(b[1:3])), 3
	default:
		return "", false
	}
	if h+n > len(b) {
		return "", false
	}
	return string(b[h : h+n]), true
}

// ---------- raw strings ----------

// analyzeStrings matches strict signatures against printable runs in the
// region's raw bytes. This catches tags in frames/boxes we don't decode.
func analyzeStrings(reg Region) []Finding {
	s := printableRuns(reg.Data, 4)
	if s == "" {
		return nil
	}
	var fs []Finding
	for _, sg := range signatures {
		if !sg.Strict {
			continue
		}
		loc := sg.Re.FindStringIndex(s)
		if loc == nil {
			continue
		}
		a := strings.LastIndexByte(s[:loc[0]+1], '\n') + 1
		b := strings.IndexByte(s[loc[1]-1:], '\n')
		if b < 0 {
			b = len(s)
		} else {
			b += loc[1] - 1
		}
		fs = append(fs, Finding{Source: "strings", Severity: sg.Severity, Location: reg.Name,
			Detail: fmt.Sprintf("%s: %q", sg.Name, clip(s[a:b], 160)), key: "sig:" + sg.Name})
	}
	return fs
}

func printableRuns(b []byte, minLen int) string {
	var sb strings.Builder
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minLen {
			sb.Write(b[start:end])
			sb.WriteByte('\n')
		}
		start = -1
	}
	for i, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\t' {
			if start < 0 {
				start = i
			}
		} else {
			flush(i)
		}
	}
	flush(len(b))
	return sb.String()
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// dedupe keeps one finding per key, preferring decoded-metadata sources over
// raw string hits and higher severity over lower.
func dedupe(fs []Finding) []Finding {
	rank := map[string]int{"c2pa": 0, "xmp": 1, "metadata": 2, "strings": 3}
	best := map[string]int{}
	var out []Finding
	for _, f := range fs {
		k := f.key
		if k == "" {
			k = f.Source + f.Location + f.Detail
		}
		if i, ok := best[k]; ok {
			o := out[i]
			if f.Severity > o.Severity || f.Severity == o.Severity && rank[f.Source] < rank[o.Source] {
				out[i] = f
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// ---------- verdict ----------

const (
	VerdictDeclared   = "AI-DECLARED"   // file's own provenance/metadata says AI made it
	VerdictLikely     = "LIKELY-AI"     // a classifier scored it above threshold
	VerdictSuspicious = "SUSPICIOUS"    // only weak/heuristic signals
	VerdictNone       = "NO-INDICATORS" // nothing found; NOT proof of human authorship
	VerdictError      = "ERROR"         // file could not be read
)

func verdict(fs []Finding) string {
	v := VerdictNone
	for _, f := range fs {
		switch {
		case f.Severity == SevStrong && !strings.HasPrefix(f.Source, "remote:"):
			return VerdictDeclared
		case f.Severity == SevStrong:
			v = VerdictLikely
		case f.Severity == SevWeak && v == VerdictNone:
			v = VerdictSuspicious
		}
	}
	return v
}
