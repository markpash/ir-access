package main

import (
	"flag"
	"fmt"
	"os"
)

const appName = "ir-access"

// Function to display help message
func showUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
	fmt.Println("Options:")
	fmt.Println("  -f, --fetch     Fetch all Iranian IP prefixes from bgp.tools.")
	fmt.Println("  -s, --setup     Set up nftables rules to Iran-Access-Only except SSH port (fetch will run automatically).")
	fmt.Println("  -h, --help      Show this help message.")
	os.Exit(0)
}

// Process command-line arguments and replace short flags with their long counterparts
func handleShortFlags() {
	for i, arg := range os.Args {
		switch arg {
		case "-h":
			showUsage()
		case "-f":
			os.Args[i] = "--fetch"
		case "-s":
			os.Args[i] = "--setup"
		}
	}
}

// Execute fetch operation
func fetch() {
	fmt.Println("Fetching IP prefixes...")
	startFetchPrefixes()
}

// Execute setup operation
func setup() {
	fmt.Println("Running fetch operation before setup...")
	fetch() // Ensure fetch is executed before setup
	startSetupNftables()
}

func main() {
	// Define command-line flags
	fetchFlag := flag.Bool("fetch", false, "Fetch all Iranian IP prefixes from bgp.tools.")
	setupFlag := flag.Bool("setup", false, "Set up nftables rules to Iran-Access-Only except SSH port.")

	// Handle short flags (-f, -s)
	handleShortFlags()

	// Parse command-line flags
	flag.Parse()

	// Check if no options were provided
	if len(os.Args) < 2 {
		fmt.Println("Error: No options provided.\n")
		showUsage()
	}

	// Execute operations based on flags
	switch {
	case *setupFlag:
		setup()
	case *fetchFlag:
		fetch()
	default:
		fmt.Println("Error: Invalid or missing options.\n")
		showUsage()
	}
}
