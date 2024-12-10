# SSDP Forwarder

A secure network packet filter for SSDP (Simple Service Discovery Protocol) traffic, specifically designed to safely handle Chromecast device discovery while protecting against potential security risks.

## Features

- Filters and forwards SSDP discovery packets
- Whitelisting of specific Chromecast device IPs
- Rate limiting to prevent DoS attacks
- Connection tracking and timeout
- Packet validation and sanity checks
- Configurable security parameters

## Prerequisites

- Rust toolchain (cargo, rustc)
- Network interface with packet capture capabilities
- Root/Administrator privileges (for packet capture)

## Installation

```bash
git clone https://github.com/yourusername/ssdp-forwarder.git
cd ssdp-forwarder
cargo build --release
```

## Usage

```bash
sudo ./target/release/ssdp-forwarder --interface <INTERFACE> --whitelist <IP1,IP2,...> [OPTIONS]
```

### Required Arguments

- `--interface`: Network interface to listen on (e.g., en0, eth0)
- `--whitelist`: Comma-separated list of whitelisted Chromecast IPv4 addresses

### Optional Arguments

- `--max-packet-size`: Maximum packet size in bytes (default: 1500)
- `--max-connections`: Maximum number of concurrent connections (default: 1000)
- `--connection-timeout`: Connection timeout in seconds (default: 30)
- `--rate-limit-window`: Rate limit window in seconds (default: 1)
- `--max-packets-per-window`: Maximum packets per rate limit window (default: 100)

### Example

```bash
sudo ./target/release/ssdp-forwarder \
  --interface en0 \
  --whitelist "192.168.1.100,192.168.1.101" \
  --max-connections 500 \
  --connection-timeout 60 \
  --max-packets-per-window 200
```

## Security Features

- Validates packet integrity and size
- Tracks and limits connection states
- Enforces rate limiting
- Only forwards packets from whitelisted devices
- Maintains connection state to prevent spoofing

## License

[Add your chosen license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
