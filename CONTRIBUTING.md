# Contributing to aidetect

Bug reports, new generator signatures and new container parsers are all welcome.
Open an issue first for anything bigger than a signature, so we can agree on the
approach before you write it.

## Setup

You need Go 1.24 or newer. There are no third-party dependencies, and a change
that adds one will not be accepted: the single static, stdlib-only binary is a
design goal.

```
git clone https://github.com/jbrahy/aidetect
cd aidetect
go test ./...
go build -o aidetect ./cmd/aidetect
```

`ffmpeg` is optional. Without it, spectral analysis only covers WAV files.

## Layout

| File | Job |
|---|---|
| `detect.go` | Public API: `Inspect`, `Options`, `Report` |
| `containers.go` | Format sniffing (`extract`) and one parser per container. Each returns `Region`s holding `Field`s (key/value) or raw bytes |
| `analyze.go` | Turns regions into `Finding`s: C2PA, IPTC `DigitalSourceType`, diffusion parameter dumps, string scans. Also `dedupe` and `verdict` |
| `signatures.go` | Table of generator names (`signatures`) and the field names that identify software (`toolKeys`) |
| `spectral.go` | Audio spectral heuristic and the ffmpeg decoder |
| `remote.go` | Opt-in remote classifiers (Hive, Sightengine) |
| `clean/` | Planning and applying removal of stale tool tags (`NewPlan`, `Apply`). One rewriter per format: `png.go`, `jpeg.go`, `audio.go` (MP3, FLAC, WAV) |
| `cmd/aidetect/` | The detector CLI. Flags, output and exit codes only; no detection logic |
| `cmd/aidetect-clean/` | The cleaner CLI. Flags, attestation, log and exit codes only |

The pipeline is: `extract` finds metadata regions, `analyzeRegions` produces
findings, the optional spectral and remote layers add more, and `verdict`
reduces them to one result. The public API stays small: put new logic behind
`Inspect` rather than exporting more.

## Common changes

### Add a generator signature

Add a `sig(...)` line to `signatures.go` under the right heading.

- **Strict** (`true`) matches anywhere in metadata. Use it only for names
  distinctive enough that they will not appear in ordinary text ("suno",
  "midjourney").
- **Non-strict** (`false`) matches only in software/encoder fields (`toolKeys`).
  Use it for ordinary words ("Sora", "Flux", "Veo"). When in doubt, use
  non-strict. A false positive on a human's file is worse than a missed match.
- **Severity**: `SevStrong` for generators, `SevInfo` for AI-*assisted*
  processing such as stem separation or mastering. Assisted processing is not
  generation and must not raise a verdict.

Then add the name to `TestSignatureBoundaries` in `aidetect_test.go`: at least
one string that must match, and one lookalike that must not.

### Add a container format

1. Write `extractXxx(r io.ReaderAt, size int64) ([]Region, error)` in
   `containers.go`.
2. Add the magic-byte case to `extract`.
3. Scan metadata only. Never scan encoded essence (`mdat`, `IDAT`, WAV `data`,
   JPEG scan data): a random byte run spelling a generator name must not match.
4. Treat all input as hostile. Bound every length read from the file against
   `size` and cap recursion depth.
5. Add a fixture builder and a case in `TestContainers`.

### Add a remote classifier

Implement the `Classifier` interface in `remote.go` (`Name`, `Supports`,
`Classify`), register it in `ParseClassifiers`, and read credentials from
environment variables, never from flags. Add a parsing test against a recorded
response body, as `TestHiveParsing` does. Remote classifiers upload the user's
file, so say so in the README section for any you add.

### Add a format to the cleaner

`clean.Apply` dispatches on the format name `aidetect` reports. A rewriter takes
the file bytes and the set of locations the plan wants gone, and returns the new
bytes plus the locations it actually removed. Rules:

1. Pick fields with `aidetect.GeneratorNames`, and build locations exactly as
   `aidetect` does (`region + " " + key`). Never write a second copy of the
   signature rules.
2. Remove only what the plan listed. Anything you cannot remove precisely, such
   as one field inside a packet that holds many, is left alone, which makes it
   an `UnsupportedError`. Do not drop a whole container to get rid of one field.
3. Prefer edits that move nothing (blank in place, or pad to the original size).
   Copy essence verbatim.
4. Test with a fixture that names the same generator in two fields:
   `aidetect.Inspect` reports one finding per generator, so a plan built from
   findings misses the second field. The plan is built from
   `aidetect.MetadataFields` for this reason.
5. Test once against a real file made by an actual tool (for audio,
   `ffmpeg -metadata comment="made with Suno" ...`) and check the decoded output
   is identical. Fixtures hide disagreements between parsers.

`Apply` re-inspects its output before writing it and refuses if anything
removable remains. Treat that as a backstop, not a substitute for the tests.

The cleaner must never gain a way to remove C2PA manifests, AI-ish IPTC
`DigitalSourceType` values or IPTC AI disclosure fields, with or without a flag.
A change that does so will not be merged.

## Tests

```
go test ./...
go vet ./...
gofmt -l .
```

CI-style checks should all be clean before you open a pull request.

- Fixtures are synthesised in the tests (one builder per container). Do not
  commit real media files: they bloat the repo and may carry rights or
  provenance problems.
- Every parser must survive truncated and corrupted input.
  `TestNoPanicOnMalformed` covers this; extend it when you add a parser.
- Add a false-positive case alongside every new positive case.

## Detection principles

These shape what gets merged:

1. **No indicators is not proof of human authorship.** Metadata is easily
   stripped and watermarks are not readable here. Wording and verdict names must
   never claim otherwise.
2. **Report what the file says, not what we infer.** C2PA manifests are read,
   not cryptographically validated, and the output says so.
3. **Weak signals stay weak.** The spectral heuristic can produce `SUSPICIOUS` at
   most, never `AI-DECLARED`. It also flags some pure human-made tones (a plain
   sine wave does), which is why it is never the basis for an accusation.
4. **Prefer a missed detection to a false accusation.** Someone's release can be
   held up by a wrong flag.

Changes to the spectral thresholds need evidence: include `-json` `spectral`
metrics from both known-AI and known-human audio, not only synthetic signals.

## Pull requests

- One logical change per PR, with tests.
- Match the surrounding code: stdlib only, comments explain why, no new
  abstractions for single-use code.
- Describe the file or tool that motivated the change (a generator's output with
  the metadata it carries is ideal; strip the audio or pixels first).
- Public API changes (anything exported) are a compatibility promise. Expect
  discussion, and note them in the PR description.

## Security

The parsers read untrusted files. If you find a crash, hang or unbounded
allocation reachable from a crafted file, please report it privately through
GitHub's "Report a vulnerability" on the Security tab rather than a public issue.

## License

By contributing you agree your work is released under the MIT license in
`LICENSE`.
