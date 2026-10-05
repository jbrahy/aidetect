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

## Cleaning false positives

Some files are flagged only because of a stale tag: an encoder field that still
says `Adobe Firefly` after a minor edit, or a `Suno` comment copied from a
project template. `aidetect-clean` writes a copy of such a file with just those
tags removed.

```
go install github.com/jbrahy/aidetect/cmd/aidetect-clean@latest
aidetect-clean -plan photo.png                        # show what would change, write nothing
aidetect-clean -attest-human-made -note "shot by me" -log clean.jsonl photo.png photo.clean.png
```

Rules it enforces:

- **It refuses any file that declares its own provenance.** That means a C2PA
  manifest, an AI-ish or unrecognised IPTC `DigitalSourceType`, or IPTC AI
  disclosure fields (`AISystemUsed` and similar). Removing a file's own claim of
  origin is not fixing a false positive. Exit status 2, nothing written.
  Human-declared values such as `digitalCapture` do not block, and are left
  untouched.
- **Writing needs `-attest-human-made`.** The tool cannot verify authorship. The
  flag is your recorded claim, saved with the optional `-note` in a JSON-lines
  `-log`, along with SHA-256 hashes of the input and output.
- **It never modifies or overwrites anything.** The output must be a new path.
  The copy is re-inspected before it is put in place, and nothing is written if
  it still looks flagged.
- **Only tags that name a tool are removed.** Diffusion parameter dumps and
  string-scan hits are reported as kept, because they are evidence of
  generation, not stale labels. Pixel, scan and audio data are copied verbatim.

| Format | What is removed |
|---|---|
| PNG | `tEXt`, `iTXt`, `zTXt` chunks |
| JPEG | comments, XMP `CreatorTool` and `softwareAgent`, EXIF text tags |
| MP3 | ID3v2.3 and 2.4 frames (the tag keeps its size) |
| FLAC | Vorbis comments and vendor string |
| WAV | RIFF INFO and `bext` text (blanked in place) |

Anything else a flagged tag sits in (XMP inside a PNG, ID3v1, APEv2, ID3v2.2,
unsynchronised ID3 tags, MP4, AIFF, Ogg) exits with status 3 and writes nothing.

What it cannot do: it does not touch the spectral heuristic, remote classifiers
or invisible watermarks. A distributor that runs a vendor watermark detector
will not be affected. As a library, use `clean.NewPlan` and `clean.Apply`.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
