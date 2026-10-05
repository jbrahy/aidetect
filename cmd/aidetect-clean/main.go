// Command aidetect-clean writes a copy of a file with stale generator-name tags
// removed, for files that aidetect flags but that were not made by generative AI.
//
//	aidetect-clean -plan photo.png                    # show what would be removed
//	aidetect-clean -attest-human-made photo.png clean.png
//
// It refuses any file that declares its own provenance (C2PA, an AI-ish IPTC
// DigitalSourceType, IPTC AI disclosure fields). It cannot verify authorship:
// -attest-human-made is your recorded claim, not a check.
//
// Exit status: 0 done or nothing to remove, 1 error, 2 refused because the file
// declares provenance, 3 a flagged field is in a place that cannot be removed.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jbrahy/aidetect/clean"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aidetect-clean", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		planOnly = fs.Bool("plan", false, "show what would be removed; write nothing")
		attest   = fs.Bool("attest-human-made", false, "assert that this file was not made by generative AI (required to write)")
		note     = fs.String("note", "", "free-text note recorded in the log")
		logPath  = fs.String("log", "", "append a JSON record of the result to this file")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: aidetect-clean -plan file\n       aidetect-clean -attest-human-made [-note text] [-log file] in out\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nexit: 0 ok, 1 error, 2 refused (declares provenance), 3 cannot remove a flagged field\n")
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	rest := fs.Args()

	if *planOnly {
		if len(rest) < 1 {
			fs.Usage()
			return 1
		}
		plan, err := clean.NewPlan(rest[0])
		if err != nil {
			return report(stderr, err)
		}
		printPlan(stdout, plan)
		return 0
	}

	if len(rest) != 2 {
		fs.Usage()
		return 1
	}
	if !*attest {
		fmt.Fprintln(stderr, "aidetect-clean: writing requires -attest-human-made, your recorded claim that this file was not made by generative AI (use -plan to just look)")
		return 1
	}
	res, err := clean.Apply(rest[0], rest[1], clean.Attestation{HumanMade: true, Note: *note})
	if err != nil {
		return report(stderr, err)
	}
	if *logPath != "" {
		if err := appendLog(*logPath, res); err != nil {
			fmt.Fprintln(stderr, "aidetect-clean: file written but the log failed:", err)
			return 1
		}
	}
	if res.Dest == "" {
		fmt.Fprintf(stdout, "%s: nothing to remove\n", res.Source)
		return 0
	}
	fmt.Fprintf(stdout, "%s -> %s\n", res.Source, res.Dest)
	for _, e := range res.Removed {
		fmt.Fprintf(stdout, "  removed %s (%s)\n", e.Location, e.Detail)
	}
	for _, u := range res.Unfixable {
		fmt.Fprintf(stdout, "  kept    %s: %s (%s)\n", u.Finding.Location, u.Finding.Detail, u.Reason)
	}
	return 0
}

func printPlan(w io.Writer, p *clean.Plan) {
	fmt.Fprintf(w, "%s [%s]\n", p.Path, p.Format)
	for _, e := range p.Remove {
		fmt.Fprintf(w, "  would remove %s (%s)\n", e.Location, e.Detail)
	}
	for _, u := range p.Unfixable {
		fmt.Fprintf(w, "  would keep   %s: %s (%s)\n", u.Finding.Location, u.Finding.Detail, u.Reason)
	}
	if len(p.Remove) == 0 && len(p.Unfixable) == 0 {
		fmt.Fprintln(w, "  nothing flagged")
	}
}

func report(w io.Writer, err error) int {
	var pe *clean.ProvenanceError
	var ue *clean.UnsupportedError
	switch {
	case errors.As(err, &pe):
		fmt.Fprintf(w, "aidetect-clean: refusing %s: it declares its own provenance, and removing that is not fixing a false positive.\n", pe.Path)
		for _, f := range pe.Findings {
			fmt.Fprintf(w, "  %s: %s\n", f.Location, f.Detail)
		}
		return 2
	case errors.As(err, &ue):
		fmt.Fprintf(w, "aidetect-clean: %v\n", ue)
		return 3
	}
	fmt.Fprintln(w, "aidetect-clean:", err)
	return 1
}

func appendLog(path string, res *clean.Result) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(res); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
