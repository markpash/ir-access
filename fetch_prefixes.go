package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	url          = "https://bgp.tools/table.jsonl"          // URL for the JSONL table dump
	userAgent    = "irgfw bgp.tools - contact@irgfw.report" // Custom User-Agent header
	outputFileV4 = "ir_prefixes_v4.txt"                     // Output file for IPv4 prefixes
	outputFileV6 = "ir_prefixes_v6.txt"                     // Output file for IPv6 prefixes
	retries      = 3                                        // Number of retries for HTTP fetch
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

// Filters prefixes by ASN
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

	return v4Prefixes, v6Prefixes
}

// Converts IPv4 prefixes to /24 blocks and writes them to a channel
func processPrefixTo24(prefix netip.Prefix, prefixChan chan<- string) {
	ip := prefix.Addr()
	prefixLen := prefix.Bits()

	if prefixLen == 24 {
		prefixChan <- prefix.String()
		return
	}

	ipInt := ipToInt(ip)
	numBlocks := 1 << (24 - prefixLen) // Calculate the number of /24 blocks
	for i := 0; i < numBlocks; i++ {
		ip := intToIP(ipInt)
		prefixChan <- netip.PrefixFrom(ip, 24).String()
		incrementIPBy24(ipInt)
	}
}

func ipToInt(ip netip.Addr) *big.Int {
	ipInt := big.NewInt(0)
	ipInt.SetBytes(ip.AsSlice())
	return ipInt
}

func intToIP(ipInt *big.Int) netip.Addr {
	ipBytes := make([]byte, 4)
	ipInt.FillBytes(ipBytes)
	ip, _ := netip.AddrFromSlice(ipBytes)
	return ip
}

func incrementIPBy24(ipInt *big.Int) {
	increment := big.NewInt(1 << 8) // 256 for /24
	ipInt.Add(ipInt, increment)
}

// Writes sorted prefixes to a file
func writePrefixesToFileV4(prefixes []netip.Prefix, outputFile string) error {
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

	uniquePrefixes := make(map[string]struct{})
	prefixChan := make(chan string, len(prefixes))
	var wg sync.WaitGroup

	for _, prefix := range prefixes {
		wg.Add(1)
		go func(p netip.Prefix) {
			defer wg.Done()
			processPrefixTo24(p, prefixChan)
		}(prefix)
	}

	go func() {
		wg.Wait()
		close(prefixChan)
	}()

	for prefix := range prefixChan {
		uniquePrefixes[prefix] = struct{}{}
	}

	sortedPrefixes := make([]string, 0, len(uniquePrefixes))
	for prefix := range uniquePrefixes {
		sortedPrefixes = append(sortedPrefixes, prefix)
	}

	sort.Strings(sortedPrefixes)
	for _, prefix := range sortedPrefixes {
		if _, err := writer.WriteString(prefix + "\n"); err != nil {
			return fmt.Errorf("writing to file: %w", err)
		}
	}

	logMessage("INFO", "Wrote %d IPv4 /24 prefixes to %s", len(sortedPrefixes), outputFile)
	return nil
}

// Writes IPv6 prefixes to a file without modification
func writePrefixesToFileV6(prefixes []netip.Prefix, outputFile string) error {
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

	sortedPrefixes := make([]netip.Prefix, len(prefixes))
	copy(sortedPrefixes, prefixes)
	sort.Slice(sortedPrefixes, func(i, j int) bool {
		return sortedPrefixes[i].String() < sortedPrefixes[j].String()
	})

	for _, prefix := range sortedPrefixes {
		if _, err := writer.WriteString(prefix.String() + "\n"); err != nil {
			return fmt.Errorf("writing to file: %w", err)
		}
	}

	logMessage("INFO", "Wrote %d IPv6 prefixes to %s", len(sortedPrefixes), outputFile)
	return nil
}

func startFetchPrefixes() {
	logMessage("INFO", "Starting processing for ASNs: %v", asnsToFilter())

	client := &http.Client{}
	prefixes, err := fetchPrefixesWithRetry(url, client, retries)
	if err != nil {
		logMessage("ERROR", "Fetching prefixes failed: %v", err)
		return
	}

	v4Prefixes, v6Prefixes := filterPrefixesByASN(prefixes, asnsToFilter())

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := writePrefixesToFileV4(v4Prefixes, outputFileV4); err != nil {
			logMessage("ERROR", "Writing IPv4 prefixes: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := writePrefixesToFileV6(v6Prefixes, outputFileV6); err != nil {
			logMessage("ERROR", "Writing IPv6 prefixes: %v", err)
		}
	}()

	wg.Wait()
	logMessage("INFO", "Processing complete.")
}
