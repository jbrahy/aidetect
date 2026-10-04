# aidetect

A Go module and console tool that checks whether an audio, image or video file shows evidence of
being made by generative AI. It is a single static binary with no third-party
dependencies: Go stdlib only, and it cross-compiles to Linux, OpenBSD and macOS.

It was built after music releases were held up by a distributor's AI-content
flag. The first job is to show what a file says about itself before anyone else
reads it.

```
go install github.com/jbrahy/aidetect/cmd/aidetect@latest
aidetect track.wav cover.png
aidetect -r -v masters/            # whole folder, show info-level findings
aidetect -json masters/*.flac | jq  # one JSON report per line
```

Exit status: `0` no indicators, `2` AI-declared or likely AI, `3` suspicious
(weak signals only), `1` error. With several files, the most severe result wins,
so you can gate a CI or upload step on it.

## Library use

```go
import "github.com/jbrahy/aidetect"

rep := aidetect.Inspect("track.wav", aidetect.Options{Spectral: true, Threshold: 0.8})
if rep.Verdict == aidetect.VerdictDeclared {
	// rep.Findings says why
}
```

`Options{}` runs the metadata checks only. Remote classifiers come from
`aidetect.ParseClassifiers("hive,sightengine")`.

## What it checks (strongest first)

| Layer | Evidence | Severity |
|---|---|---|
| **Provenance** | C2PA / Content Credentials manifest (JPEG APP11, PNG, MP4 `uuid`, WebP…); IPTC `DigitalSourceType` in XMP or C2PA: `trainedAlgorithmicMedia`, `compositeWithTrainedAlgorithmicMedia` | strong |
| **Generator metadata** | Tool names (Suno, Udio, Stable Audio, ElevenLabs, AIVA, Boomy, Mubert, Midjourney, DALL·E, Firefly, SD/ComfyUI/A1111, Sora, Runway, Veo…) found in ID3v1/v2.2–2.4, APEv2, FLAC/Vorbis comments, RIFF INFO/`bext`, AIFF, MP4 `ilst`/`udta`, EXIF, XMP, PNG `tEXt`/`iTXt`/`zTXt`. Also diffusion parameter dumps, ComfyUI graphs, and IPTC 2025 `AISystemUsed` fields | strong |
| **Classifier** (`-remote`, opt-in) | Hive (any media, depending on the key's project) or Sightengine `genai` (images). Score ≥ `-threshold` (default 0.8) counts as strong, ≥ half of it as weak | strong / weak |
| **Spectral heuristic** (audio) | Stationary, narrow high-frequency peaks and a regular comb in the time-averaged spectrum. These are the upsampling artifacts that neural audio decoders leave behind (Afchar et al., Deezer Research, 2024) | weak at most |

Only structural metadata regions are scanned. Encoded essence (`mdat`, `IDAT`, WAV
`data`, JPEG scan data) is skipped, so a random byte run that happens to spell
"suno" can't trigger a match. Ordinary-word names (Sora, Flux, Loudly, Veo,
Gemini, Firefly) match only in software/encoder fields, never in titles or
comments.

AI-*assisted* processing (LANDR, Moises, LALAL.AI, Demucs, Topaz…) is reported
at info level. It isn't generation, but a distributor may still care about it.

## Limits

- **`NO-INDICATORS` does not mean human-made.** Metadata can be stripped with one
  ffmpeg command. Most generator exports carry little or none.
- **Invisible watermarks can't be detected here.** That includes Google SynthID,
  Meta AudioSeal and whatever Suno/Udio embed. Only the vendor's own detector can
  read them, and that is almost certainly what distributors run. A clean result
  from this tool will not clear a distributor flag.
- **C2PA signatures are not validated.** The tool reports what the manifest claims.
  To verify it cryptographically, run
  [`c2patool`](https://github.com/contentauth/c2patool).
- **The spectral heuristic is uncalibrated.** Thresholds were set against
  synthetic signals. On those, a 1 kHz artifact comb was found exactly, and clean
  and looped material stayed clean. Before trusting it, run it on 20–30 known-human
  masters from the same producers and compare `-json` `spectral` metrics. Lossy
  sources (MP3/AAC), pitch-shifting and heavy mastering degrade it. On its own it
  can never produce more than `SUSPICIOUS`.
- **Only WAV is decoded natively for spectral analysis.** Every other format needs
  `ffmpeg` on `PATH` (it also reads video audio tracks).

## Remote classifiers

```
export HIVE_API_KEY=...
export SIGHTENGINE_API_USER=... SIGHTENGINE_API_SECRET=...
aidetect -remote hive,sightengine file.jpg
```

`-remote` **uploads the whole file to a third party.** Don't point it at unreleased
masters without checking the vendor's retention and training terms. The response
parsing follows the vendors' published formats. It is covered by unit tests but
has not been run against live keys.

## Tests

```
go test ./...
```

Fixtures are synthesised in the tests, one per container, plus false-positive
cases. The tests also fuzz truncated and corrupted inputs to make sure the
parsers never panic.
