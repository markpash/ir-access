# IR-Access

**IR-Access** is a Go-based application designed to fetch Iranian IP prefixes and set up firewall rules using `nftables` to allow only Iranian traffic while keeping SSH access open.

## Features

- Fetches Iranian IP prefixes from [bgp.tools](https://bgp.tools/table.jsonl)
- Filters the IP prefixes based on predefined ASN numbers
- Converts IPv4 prefixes to /24 blocks
- Configures `nftables` to allow traffic only from Iran (except SSH)
- Automated setup and verification

## Prerequisites

Ensure the following dependencies are installed on your system:

- **Go (>=1.22)**
- **nftables**
- **sudo privileges** (for setup operation)

## Run

### Linux:

All binaries are available in `amd64` and `arm64`.

1.
    ```
    wget "https://github.com/irgfw/ir-access/releases/latest/download/ir-access-$(uname -s | tr A-Z a-z)-amd64" -O ir-access && chmod +x ir-access
    ```
2. 
    ```
    ./ir-access -f
    ```
    
### Windows:

1. Download from [Releases](https://github.com/irgfw/ir-access/releases/latest).
2. Open `CMD` or `Powershell` in the directory.
3.
    ```
    .\ir-access-windows-amd64.exe --fetch
    ```

## Build

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/IR-Access.git
    cd IR-Access
    ```

2. Build the application:

    ```sh
    go build -o ir-access
    ```

## Usage

Run the application with the following options:

```sh
./ir-access [OPTIONS]
```

### Available Options

| Option   | Short Flag | Description                                                           |
|----------|------------|-----------------------------------------------------------------------|
| `--fetch` | `-f`       | Fetch all Iranian IP prefixes from bgp.tools.                        |
| `--setup` | `-s`       | Set up nftables rules to allow Iran-only access (fetches prefixes).  |
| `--help`  | `-h`       | Show help message.                                                   |

### Examples

- Fetch Iranian IP prefixes:

  ```sh
  ./ir-access --fetch
  ```

- Set up firewall rules to allow Iran-Only access (excluding SSH):

  ```sh
  sudo ./ir-access --setup
  ```

#### Note that for now, only Ubuntu _(>22)_ and Debian _(>11)_ are supported for the `-s` or `—-setup` flag.

## How It Works

1. **Fetching Prefixes:**
    - Downloads the IP prefix data from `bgp.tools`.
    - Filters the prefixes based on specific ASN numbers.
    - Saves IPv4 and IPv6 prefixes into respective text files.

2. **Setting Up nftables:**
    - Reads the stored prefix files.
    - Detects the SSH port from `/etc/ssh/sshd_config`.
    - Configures firewall rules to allow only Iranian traffic.
    - Applies and verifies the nftables rules.

## License

This project is licensed under the MIT License.

## Contributions

Contributions are welcome! Feel free to fork the repository and submit a pull request.
