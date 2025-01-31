package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const appName = "ir-access"

// Execute fetch operation
func fetch(l *slog.Logger) {
	l.Info("fetching IP prefixes")
	startFetchPrefixes(l)
}

// Execute setup operation
func setup(l *slog.Logger) {
	l.Info("running fetch operation before setup...")
	fetch(l) // Ensure fetch is executed before setup
	startSetupNftables(l)
}

func main() {
	// Define command-line flags
	fs := ff.NewFlagSet(appName)
	fetchFlag := fs.Bool('f', "fetch", "Fetch all Iranian IP prefixes from bgp.tools.")
	setupFlag := fs.Bool('s', "setup", "Set up nftables rules to Iran-Access-Only except SSH port.")
	verboseFlag := fs.Bool('v', "verbose", "Enable verbose logging")

	err := ff.Parse(fs, os.Args[1:])
	switch {
	case errors.Is(err, ff.ErrHelp):
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *verboseFlag {
		l = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// Execute operations based on flags
	switch {
	case *setupFlag:
		setup(l)
	case *fetchFlag:
		fetch(l)
	default:
		fmt.Fprintf(os.Stderr, "error: invalid or missing options\n")
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
		os.Exit(1)
	}
}
