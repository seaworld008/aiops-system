package main

import (
	"flag"
	"log/slog"
	"os"
)

func main() {
	mode := flag.String("mode", "read", "runner mode: read or write")
	flag.Parse()
	if *mode != "read" && *mode != "write" {
		slog.Error("invalid runner mode", "mode", *mode)
		os.Exit(2)
	}
	slog.Info("environment runner bootstrap", "mode", *mode)
}
