package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	ipv4File      = "ir_prefixes_v4.txt"
	ipv6File      = "ir_prefixes_v6.txt"
	nftablesConf  = "/etc/nftables.conf"
	sshConfigPath = "/etc/ssh/sshd_config"
)

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func prepare() {
	fmt.Println("\nPreparing nftables setup...\n")
	time.Sleep(500 * time.Millisecond)
	runCommand("sudo", "apt", "update", "-qq")
	time.Sleep(500 * time.Millisecond)
	runCommand("sudo", "apt", "install", "-qqy", "nftables")
}

func findSSHPort() string {
	fmt.Println("\nFinding SSH port...")
	file, err := os.Open(sshConfigPath)
	if err != nil {
		fmt.Println("\nSSH configuration file not found, using default port 22.")
		return "22"
	}
	defer file.Close()

	re := regexp.MustCompile(`^Port\s+(\d+)`)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if match := re.FindStringSubmatch(scanner.Text()); match != nil {
			fmt.Printf("\nSSH port found: %s\n", match[1])
			return match[1]
		}
	}

	fmt.Println("\nSSH port is default 22.")
	return "22"
}

func readPrefixes(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error: file '%s' not found", filePath)
	}
	defer file.Close()

	var prefixes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			prefixes = append(prefixes, line)
		}
	}
	return prefixes, nil
}

func initializeNftablesConf(sshPort string) {
	fmt.Println("\nInitializing nftables configuration...")

	ipv4Prefixes, err := readPrefixes(ipv4File)
	if err != nil {
		fmt.Println(err)
		ipv4Prefixes = []string{}
	}

	ipv6Prefixes, err := readPrefixes(ipv6File)
	if err != nil {
		fmt.Println(err)
		ipv6Prefixes = []string{}
	}

	file, err := os.Create(nftablesConf)
	if err != nil {
		fmt.Println("Error creating nftables.conf:", err)
		return
	}
	defer file.Close()

	// Define default configuration
	config := `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
`

	// Add IPv4 set if not empty
	if len(ipv4Prefixes) > 0 {
		config += `    set allowed_ipv4 {
        type ipv4_addr; flags interval; auto-merge;
        elements = {` + strings.Join(ipv4Prefixes, ",\n") + `}
    }
`
	}

	// Add IPv6 set if not empty
	if len(ipv6Prefixes) > 0 {
		config += `    set allowed_ipv6 {
        type ipv6_addr; flags interval; auto-merge;
        elements = {` + strings.Join(ipv6Prefixes, ",\n") + `}
    }
`
	}

	// Add the chain configuration
	config += fmt.Sprintf(`    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iif lo accept
        tcp dport %s accept
`, sshPort)

	// Add conditions based on the sets
	if len(ipv4Prefixes) > 0 {
		config += `        ip saddr @allowed_ipv4 accept
`
	}
	if len(ipv6Prefixes) > 0 {
		config += `        ip6 saddr @allowed_ipv6 accept
`
	}

	// Close configuration
	config += `    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
`

	_, err = file.WriteString(config)
	if err != nil {
		fmt.Println("Error writing nftables.conf:", err)
	}

	fmt.Println("\nNFTables configuration initialized.")
}

func applyNftables() {
	fmt.Println("\nApplying nftables configuration...\n")
	time.Sleep(500 * time.Millisecond)

	err := runCommand("sudo", "nft", "-f", nftablesConf)
	if err != nil {
		fmt.Println("Error: Failed to apply nftables configuration.")
		os.Exit(1)
	}

	fmt.Println("Enabling nftables service...\n")
	runCommand("sudo", "systemctl", "enable", "nftables")
	runCommand("sudo", "systemctl", "start", "nftables")
	fmt.Println("Configuration applied and nftables service started.\n")
}

func verifyNftables() {
	fmt.Println("\nVerifying nftables ruleset...\n")
	runCommand("sudo", "nft", "list", "ruleset")
}

func startSetupNftables() {
	prepare()
	time.Sleep(time.Second)
	sshPort := findSSHPort()
	time.Sleep(time.Second)
	initializeNftablesConf(sshPort)
	time.Sleep(time.Second)
	applyNftables()
	time.Sleep(time.Second)
	verifyNftables()
	time.Sleep(time.Second)

	fmt.Println("\nNftables setup is complete. Your server is now Iran-Access-Only except for SSH port.")
	fmt.Printf("Configuration is saved in %s.\n", nftablesConf)
}
