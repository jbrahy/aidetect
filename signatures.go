package aidetect

import (
	"regexp"
	"strings"
)

// Signature is a known generator/tool name.
//
// Strict signatures are distinctive enough to match anywhere: any metadata
// field, or any printable string pulled out of a metadata region. Non-strict
// ones are ordinary words ("Sora", "Flux", "Loudly") and only count when they
// show up in a field that names the producing software, never in free text.
type Signature struct {
	Name     string
	Re       *regexp.Regexp
	Strict   bool
	Severity Severity
	Note     string
}

func sig(name string, strict bool, sev Severity, pattern string) Signature {
	return Signature{Name: name, Strict: strict, Severity: sev, Re: regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:` + pattern + `)(?:$|[^a-z0-9])`)}
}

var signatures = []Signature{
	// --- Generative music / audio / voice ---
	sig("Suno", true, SevStrong, `suno(?:\s*ai)?|suno\.com|made with suno`),
	sig("Udio", true, SevStrong, `udio(?:\.com)?`),
	sig("Stable Audio", true, SevStrong, `stable\s*audio`),
	sig("Stability AI", true, SevStrong, `stability\s*ai|stability\.ai`),
	sig("AIVA", true, SevStrong, `aiva(?:\.ai)?`),
	sig("Boomy", true, SevStrong, `boomy`),
	sig("Soundraw", true, SevStrong, `soundraw`),
	sig("Mubert", true, SevStrong, `mubert`),
	sig("Riffusion", true, SevStrong, `riffusion`),
	sig("ElevenLabs", true, SevStrong, `eleven\s*labs|elevenlabs\.io`),
	sig("MusicGen/AudioCraft", true, SevStrong, `musicgen|audiocraft`),
	sig("Beatoven", true, SevStrong, `beatoven(?:\.ai)?`),
	sig("Soundful", true, SevStrong, `soundful`),
	sig("Loudly", false, SevStrong, `loudly`),
	sig("Lyria", false, SevStrong, `lyria`),
	sig("MiniMax/Hailuo", false, SevStrong, `minimax|hailuo`),

	// --- Generative image / video ---
	sig("Midjourney", true, SevStrong, `midjourney`),
	sig("DALL·E", true, SevStrong, `dall[\s\-·]?e(?:\s*[23])?`),
	sig("OpenAI", true, SevStrong, `openai|chatgpt|gpt-?4o|gpt-image`),
	sig("Stable Diffusion", true, SevStrong, `stable[\s\-]?diffusion|sdxl|dreamstudio`),
	sig("ComfyUI", true, SevStrong, `comfyui`),
	sig("AUTOMATIC1111", true, SevStrong, `automatic1111|a1111`),
	sig("InvokeAI", true, SevStrong, `invokeai`),
	sig("Fooocus", true, SevStrong, `fooocus`),
	sig("NovelAI", true, SevStrong, `novelai`),
	sig("Adobe Firefly", true, SevStrong, `adobe[\s_]firefly`),
	sig("Firefly", false, SevStrong, `firefly`),
	sig("Leonardo.Ai", true, SevStrong, `leonardo\.ai`),
	sig("Ideogram", true, SevStrong, `ideogram`),
	sig("FLUX", true, SevStrong, `flux\.1|black\s*forest\s*labs`),
	sig("FLUX", false, SevStrong, `flux`),
	sig("Google (Imagen/Gemini/Veo)", true, SevStrong, `made with google ai|google\s*imagen|imagen\s*[234]`),
	sig("Google (Imagen/Gemini/Veo)", false, SevStrong, `imagen|gemini|veo`),
	sig("Runway", true, SevStrong, `runwayml|runway\s*gen-?[1-4]`),
	sig("Sora", false, SevStrong, `sora`),
	sig("Kling", true, SevStrong, `kling\s*ai|klingai`),
	sig("Luma Dream Machine", true, SevStrong, `dream\s*machine|lumalabs`),
	sig("Pika", false, SevStrong, `pika(?:\s*labs)?`),
	sig("HeyGen", true, SevStrong, `heygen`),
	sig("Synthesia", true, SevStrong, `synthesia`),
	sig("Grok", false, SevStrong, `grok(?:\s*imagine)?`),
	sig("Playground AI", true, SevStrong, `playground\s*ai|playgroundai`),
	sig("Krea", true, SevStrong, `krea\.ai`),

	// --- Explicit self-declarations ---
	sig("AI-generated label", true, SevStrong, `ai[\s\-]generated|generated (?:by|with) ai|created (?:by|with) ai|synthetic media`),

	// --- AI-assisted processing (not generation; context for disputes) ---
	sig("LANDR", true, SevInfo, `landr`),
	sig("Moises", true, SevInfo, `moises(?:\.ai)?`),
	sig("LALAL.AI", true, SevInfo, `lalal\.ai`),
	sig("Demucs/Spleeter (stem separation)", true, SevInfo, `demucs|spleeter`),
	sig("Adobe Podcast Enhance", true, SevInfo, `adobe podcast|enhance speech`),
	sig("Topaz AI", true, SevInfo, `topaz (?:video|photo|gigapixel)`),
	sig("Photoshop Generative Fill", true, SevStrong, `generative (?:fill|expand)`),
}

// toolKeys are field names whose value identifies the producing software.
// Non-strict signatures only match here.
var toolKeys = map[string]bool{
	"tsse": true, "tenc": true, "tss": true, "ten": true, "©too": true, "©enc": true, "©swr": true, "©swf": true,
	"isft": true, "software": true, "creatortool": true, "encoder": true, "encodedby": true, "encoded_by": true,
	"encoded-by": true, "vendor": true, "claim_generator": true, "softwareagent": true, "generator": true, "tool": true,
	"bext:originator": true, "producer": true,
}

func isToolKey(k string) bool {
	k = strings.ToLower(k)
	if i := strings.LastIndexByte(k, ':'); i >= 0 && !strings.HasPrefix(k, "bext:") {
		k = k[i+1:]
	}
	return toolKeys[strings.ReplaceAll(k, " ", "")]
}

func matchSignatures(s string, toolField bool) []Signature {
	var out []Signature
	seen := map[string]bool{}
	for _, sg := range signatures {
		if !sg.Strict && !toolField {
			continue
		}
		if seen[sg.Name] {
			continue
		}
		if sg.Re.MatchString(s) {
			seen[sg.Name] = true
			out = append(out, sg)
		}
	}
	return out
}

// IPTC Digital Source Type vocabulary. Used by IPTC/XMP and by C2PA actions.
// https://cv.iptc.org/newscodes/digitalsourcetype/
var digitalSourceTypes = map[string]struct {
	Sev  Severity
	Desc string
}{
	"trainedalgorithmicmedia":              {SevStrong, "fully generated by a trained AI model"},
	"compositewithtrainedalgorithmicmedia": {SevStrong, "composite that includes AI-generated elements"},
	"algorithmicmedia":                     {SevWeak, "algorithmically generated (not necessarily ML)"},
	"compositesynthetic":                   {SevWeak, "composite including synthetic elements"},
	"algorithmicallyenhanced":              {SevInfo, "human-made, algorithmically enhanced"},
	"datadrivenmedia":                      {SevInfo, "generated from data (not a trained model)"},
	"digitalcapture":                       {SevInfo, "declared as an original digital capture"},
	"virtualrecording":                     {SevInfo, "declared as a live recording of virtual content"},
	"humanedits":                           {SevInfo, "declared human-edited"},
	"minorhumanedits":                      {SevInfo, "declared human-edited (minor)"},
	"composite":                            {SevInfo, "declared composite"},
	"compositecapture":                     {SevInfo, "declared composite of captures"},
	"digitalart":                           {SevInfo, "declared human-made digital art"},
	"screencapture":                        {SevInfo, "declared screen capture"},
	"negativefilm":                         {SevInfo, "declared scanned film"},
	"positivefilm":                         {SevInfo, "declared scanned film"},
	"print":                                {SevInfo, "declared scanned print"},
}

// GeneratorNames returns the names of the known generators that value matches
// when it is stored in the metadata field called key. It applies the same rules
// as Inspect: ordinary-word signatures only match in fields that name the
// producing software. Tools that rewrite metadata use it to pick the same
// fields Inspect flagged.
func GeneratorNames(key, value string) []string {
	var out []string
	for _, sg := range matchSignatures(value, isToolKey(key)) {
		if sg.Severity >= SevWeak {
			out = append(out, sg.Name)
		}
	}
	return out
}
