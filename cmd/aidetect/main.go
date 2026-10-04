// Command aidetect checks audio, image and video files for evidence of
// generative-AI origin. See the aidetect package for what it checks and its limits.
//
// Exit status: 0 no indicators, 1 error, 2 AI-declared or likely AI,
// 3 suspicious (weak signals only). With several files, the highest wins.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jbrahy/aidetect"
)

func main() {
	var (
		jsonOut   = flag.Bool("json", false, "emit one JSON report per line")
		recursive = flag.Bool("r", false, "recurse into directories")
		noSpec    = flag.Bool("no-spectral", false, "skip the audio spectral heuristic")
		remote    = flag.String("remote", "", "comma-separated classifiers to UPLOAD the file to: hive, sightengine")
		threshold = flag.Float64("threshold", 0.8, "classifier score treated as likely AI")
		verbose   = flag.Bool("v", false, "also print info-level findings and spectral metrics")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: aidetect [flags] file|dir ...\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nexit: 0 no indicators, 1 error, 2 AI-declared/likely AI, 3 suspicious\n")
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	opt := aidetect.Options{Spectral: !*noSpec, Threshold: *threshold}
	if p, err := exec.LookPath("ffmpeg"); err == nil {
		opt.FFmpeg = p
	}
	cs, err := aidetect.ParseClassifiers(*remote)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aidetect:", err)
		os.Exit(1)
	}
	opt.Classifiers = cs

	exit := 0
	bump := func(code int) {
		// severity order: 0 < 3 < 2; errors (1) only win over "nothing found"
		rank := map[int]int{0: 0, 1: 1, 3: 2, 2: 3}
		if rank[code] > rank[exit] {
			exit = code
		}
	}
	enc := json.NewEncoder(os.Stdout)
	for _, arg := range flag.Args() {
		for _, p := range expand(arg, *recursive) {
			rep := aidetect.Inspect(p, opt)
			if *jsonOut {
				enc.Encode(rep)
			} else {
				printReport(rep, *verbose)
			}
			switch {
			case rep.Verdict == aidetect.VerdictError:
				bump(1)
			case rep.Verdict == aidetect.VerdictDeclared || rep.Verdict == aidetect.VerdictLikely:
				bump(2)
			case rep.Verdict == aidetect.VerdictSuspicious:
				bump(3)
			}
		}
	}
	os.Exit(exit)
}

func expand(arg string, recursive bool) []string {
	st, err := os.Stat(arg)
	if err != nil || !st.IsDir() {
		return []string{arg}
	}
	var out []string
	filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return nil
		case d.IsDir() && p != arg && (!recursive || strings.HasPrefix(d.Name(), ".")):
			return filepath.SkipDir
		case d.Type().IsRegular() && !strings.HasPrefix(d.Name(), "."):
			out = append(out, p)
		}
		return nil
	})
	return out
}

func printReport(r aidetect.Report, verbose bool) {
	if r.Format == "" {
		fmt.Printf("%s\n  verdict: %s\n", r.Path, r.Verdict)
	} else {
		fmt.Printf("%s  [%s, %s]\n  verdict: %s\n", r.Path, r.Format, humanSize(r.Size), r.Verdict)
	}
	shown := 0
	for _, f := range r.Findings {
		if f.Severity == aidetect.SevInfo && !verbose {
			continue
		}
		fmt.Printf("  %-6s %-18s %s — %s\n", f.Severity, f.Source, f.Location, f.Detail)
		shown++
	}
	if hidden := len(r.Findings) - shown; hidden > 0 {
		fmt.Printf("  (%d info finding(s) hidden; -v to show)\n", hidden)
	}
	if verbose && r.Spectral != nil {
		s := r.Spectral
		fmt.Printf("  spectral: %s %d Hz, %.0fs, %d frames, peaks=%v\n", s.Decoder, s.SampleRate, s.Seconds, s.Frames, s.PeakFreqsHz)
	}
	for _, n := range r.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	for _, e := range r.Errors {
		fmt.Printf("  error: %s\n", e)
	}
	if r.Verdict == aidetect.VerdictNone {
		fmt.Println("  note: no indicators ≠ human-made; stripped metadata and invisible watermarks are not detectable here")
	}
	fmt.Println()
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
