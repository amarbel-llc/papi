package installer

import (
	"io"
	"os"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
	"github.com/amarbel-llc/crap/go-crap/v2/viewport"
)

// Present runs produce against a crap.Reporter and renders the resulting
// ndjson-crap stream: a live viewport when out is a TTY, else the raw ndjson-crap
// on out. It mirrors papi's root presentCrapOp (main.go) — duplicated here so the
// installer engine never imports package main (which keeps this change disjoint
// from concurrent main.go edits). produce's returned error is the run verdict.
func Present(out io.Writer, opts crap.ReporterOptions, title string, produce func(*crap.Reporter) error) error {
	if !isTerminal(out) {
		rep := crap.NewReporter(out, opts)
		err := produce(rep)
		if err == nil {
			err = rep.Err()
		}
		return err
	}
	// TTY: feed the producer's records through a pipe into the live viewport, which
	// renders to out. The viewport never reads the data pipe as keyboard input.
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		rep := crap.NewReporter(pw, opts)
		err := produce(rep)
		if err == nil {
			err = rep.Err()
		}
		_ = pw.Close() // EOF → the viewport quits
		done <- err
	}()
	verr := viewport.Present(pr, viewport.Options{Title: title, Out: out, IsTTY: true})
	if perr := <-done; perr != nil {
		return perr
	}
	return verr
}

// isTerminal reports whether w is a character device (a TTY).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}
