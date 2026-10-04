// Package aidetect inspects media files (audio, image, video) for evidence that
// they were produced by a generative AI system.
//
// Evidence, strongest first:
//
//  1. Provenance the file carries about itself: C2PA / Content Credentials
//     manifests and IPTC DigitalSourceType (trainedAlgorithmicMedia).
//  2. Generator fingerprints in metadata: tool names in ID3/Vorbis/RIFF/MP4/
//     EXIF/XMP/PNG tags, diffusion parameter dumps, ComfyUI graphs.
//  3. Optional third-party classifiers (Options.Classifiers), for stripped files.
//  4. A spectral heuristic for neural-decoder audio artifacts (weak signal).
//
// Absence of evidence is not evidence of human authorship: metadata is
// trivially stripped, and invisible watermarks (SynthID, AudioSeal, vendor
// watermarks) require the vendor's own detector.
package aidetect

import "os"

// Report is the result of inspecting one file.
type Report struct {
	Path     string           `json:"path"`
	Format   string           `json:"format"`
	Size     int64            `json:"size"`
	Verdict  string           `json:"verdict"`
	Findings []Finding        `json:"findings"`
	Spectral *SpectralMetrics `json:"spectral,omitempty"`
	Notes    []string         `json:"notes,omitempty"`
	Errors   []string         `json:"errors,omitempty"`
}

// Options controls an inspection. The zero value runs the metadata checks only.
type Options struct {
	// Spectral enables the audio spectral heuristic.
	Spectral bool
	// FFmpeg is the path to ffmpeg, used to decode non-WAV audio. Empty means
	// non-WAV audio is skipped with a note.
	FFmpeg string
	// Classifiers are remote services the file is UPLOADED to. See ParseClassifiers.
	Classifiers []Classifier
	// Threshold is the classifier score treated as likely AI.
	Threshold float64
}

var audioFormats = map[string]bool{"wave": true, "mp3": true, "mpeg-audio": true, "flac": true, "aiff": true, "aifc": true, "ogg": true, "isobmff": true, "matroska": true}

// Inspect analyses the file at path. Problems reading the file are reported in
// Report.Errors with Verdict VerdictError; Inspect itself never fails.
func Inspect(path string, opt Options) Report {
	rep := Report{Path: path, Verdict: VerdictError, Findings: []Finding{}}
	f, err := os.Open(path)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep
	}
	rep.Size = st.Size()

	format, regions, err := extract(f, rep.Size)
	rep.Format = format
	if err != nil {
		rep.Errors = append(rep.Errors, "parse: "+err.Error())
	}
	rep.Findings = analyzeRegions(regions)

	if opt.Spectral && audioFormats[format] {
		m, fs, err := spectralAnalyze(path, format, f, rep.Size, opt.FFmpeg)
		if err == errNoDecoder {
			rep.Notes = append(rep.Notes, "spectral skipped: install ffmpeg to analyze non-WAV audio")
		} else if err != nil {
			rep.Errors = append(rep.Errors, "spectral: "+err.Error())
		}
		rep.Spectral = m
		rep.Findings = append(rep.Findings, fs...)
	}
	rep.Findings = append(rep.Findings, runClassifiers(opt.Classifiers, path, format, opt.Threshold)...)
	rep.Findings = dedupe(rep.Findings)
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	rep.Verdict = verdict(rep.Findings)
	return rep
}
