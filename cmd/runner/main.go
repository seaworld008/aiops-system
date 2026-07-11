package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("runner startup rejected", "error", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("runner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "read", "runner mode: read or write")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse runner flags: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected runner arguments")
	}

	switch *mode {
	case "read":
		slog.Info("environment runner bootstrap", "mode", *mode)
		return nil
	case "write":
		return errors.New("write runner is unavailable until the isolated executor and mTLS gateway are implemented")
	default:
		return fmt.Errorf("invalid runner mode %q: must be read or write", *mode)
	}
}
