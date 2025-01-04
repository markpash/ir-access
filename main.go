package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	url          = "https://bgp.tools/table.jsonl" // URL for the JSONL table dump
	userAgent    = "bgp.tools script"              // Custom User-Agent header
	outputFileV4 = "ir_prefixes_v4.txt"            // Output file for IPv4 prefixes
	outputFileV6 = "ir_prefixes_v6.txt"            // Output file for IPv6 prefixes
	retries      = 3                               // Number of retries for HTTP fetch
)

// Enhanced logging setup
func init() {
	log.SetFlags(0)   // Disable default timestamp
	log.SetPrefix("") // No default prefix
}

// Custom logger function
func logMessage(level string, msg string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	formattedLevel := fmt.Sprintf("[%s]", level)
	fmt.Printf("%s %-7s %s\n", timestamp, formattedLevel, fmt.Sprintf(msg, args...))
}

// Prefix structure for JSON parsing
type Prefix struct {
	CIDR netip.Prefix `json:"CIDR"`
	ASN  int          `json:"ASN"`
}

// Fetch prefixes with retry logic
func fetchPrefixesWithRetry(url string, client *http.Client, retries int) ([]Prefix, error) {
	var prefixes []Prefix
	var err error
	for i := 0; i < retries; i++ {
		prefixes, err = fetchPrefixes(url, client)
		if err == nil {
			return prefixes, nil
		}
		logMessage("WARN", "Fetch failed (attempt %d/%d): %v", i+1, retries, err)
		time.Sleep(2 * time.Second) // Backoff between retries
	}
	return nil, fmt.Errorf("all fetch attempts failed: %w", err)
}

// Fetches prefixes from the URL
func fetchPrefixes(url string, client *http.Client) ([]Prefix, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	var prefixes []Prefix
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var prefix Prefix
		if err := json.Unmarshal(scanner.Bytes(), &prefix); err != nil {
			logMessage("WARN", "Skipping invalid JSON line: %v", err)
			continue
		}
		prefixes = append(prefixes, prefix)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return prefixes, nil
}

// Filters prefixes by ASN and separates IPv4/IPv6 using channels
func filterPrefixesByASN(prefixes []Prefix, asns []int) ([]netip.Prefix, []netip.Prefix) {
	asnSet := make(map[int]struct{})
	for _, asn := range asns {
		asnSet[asn] = struct{}{}
	}

	var v4Prefixes, v6Prefixes []netip.Prefix
	for _, prefix := range prefixes {
		if _, exists := asnSet[prefix.ASN]; exists {
			if prefix.CIDR.Addr().Is4() {
				v4Prefixes = append(v4Prefixes, prefix.CIDR)
			} else if prefix.CIDR.Addr().Is6() {
				v6Prefixes = append(v6Prefixes, prefix.CIDR)
			}
		}
	}

	return deduplicatePrefixes(v4Prefixes), deduplicatePrefixes(v6Prefixes)
}

// Deduplicates prefixes by removing overlaps, keeping only broader ones
func deduplicatePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	// Sort prefixes by prefix length (shorter first for broader prefixes)
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].Bits() < prefixes[j].Bits()
	})

	var result []netip.Prefix
	for _, current := range prefixes {
		overlap := false
		for _, existing := range result {
			if existing.Contains(current.Addr()) {
				overlap = true
				break
			}
		}
		if !overlap {
			result = append(result, current)
		}
	}

	return result
}

// Writes sorted prefixes to a file
func writePrefixesToFile(prefixes []netip.Prefix, outputFile string) error {
	if len(prefixes) == 0 {
		logMessage("INFO", "No prefixes to write to %s", outputFile)
		return nil
	}

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	sort.Slice(prefixes, func(i, j int) bool {
		return strings.Compare(prefixes[i].String(), prefixes[j].String()) < 0
	})

	for _, prefix := range prefixes {
		if _, err := writer.WriteString(prefix.String() + "\n"); err != nil {
			return fmt.Errorf("writing to file: %w", err)
		}
	}

	logMessage("INFO", "Wrote %d prefixes to %s", len(prefixes), outputFile)
	return nil
}

func main() {
	// List of ASNs to filter
	asnsToFilter := []int{
		197207, 44244, 25184, 41689, 12880, 49100, 41881, 50810,
		47330, 48159, 58224, 42337, 24631, 39501, 51469, 205647,
		31549, 57218, 25124, 42440, 60976, 16322,
	}

	logMessage("INFO", "Starting processing for ASNs: %v", asnsToFilter)

	client := &http.Client{}
	prefixes, err := fetchPrefixesWithRetry(url, client, retries)
	if err != nil {
		logMessage("ERROR", "Fetching prefixes failed: %v", err)
		return
	}

	v4Prefixes, v6Prefixes := filterPrefixesByASN(prefixes, asnsToFilter)

	// Write IPv4 and IPv6 prefixes concurrently
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := writePrefixesToFile(v4Prefixes, outputFileV4); err != nil {
			logMessage("ERROR", "Writing IPv4 prefixes: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := writePrefixesToFile(v6Prefixes, outputFileV6); err != nil {
			logMessage("ERROR", "Writing IPv6 prefixes: %v", err)
		}
	}()

	wg.Wait()
	logMessage("INFO", "Processing complete.")
}
