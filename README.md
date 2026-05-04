# NetArp

Network device discovery using ARP scanning, with a GraphQL API.

## Requirements

- Rust (edition 2024)
- Root/admin privileges (required for raw socket ARP)

## Build

```bash
cargo build --release
```

## Usage

```bash
sudo RUST_LOG=info ./target/release/netarp [OPTIONS]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --interface` | auto-detect | Network interface to scan on |
| `-s, --subnet` | auto-detect | Subnet in CIDR notation (e.g. `192.168.1.0/24`) |
| `-I, --interval` | `300` | Scan interval in seconds |
| `-p, --port` | `4000` | GraphQL API server port |
| `--db-path` | `netarp.db` | Database path |

### Examples

```bash
# Auto-detect everything
sudo RUST_LOG=info ./target/release/netarp

# Scan a specific subnet every 60 seconds
sudo RUST_LOG=info ./target/release/netarp -s 192.168.1.0/24 -I 60

# Use a specific interface
sudo RUST_LOG=info ./target/release/netarp -i en0

# Suppress noisy warnings
sudo RUST_LOG=info,warn=off ./target/release/netarp
```

## GraphQL API

The API runs at `http://localhost:4000/graphql` with an interactive Playground at the same URL in a browser.

### Queries

**All devices**
```graphql
{ allDevices { ip mac alias vendor firstSeen lastSeen } }
```

**Recently seen devices (within N minutes)**
```graphql
{ latestDevices(withinMinutes: 10) { ip mac alias vendor firstSeen lastSeen } }
```

**Device history by MAC**
```graphql
{ deviceHistory(mac: "20:df:b9:0d:82:59") { deviceMac timestamp kind detail } }
```

### curl examples

```bash
# List all devices
curl -s -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ allDevices { ip mac alias vendor firstSeen lastSeen } }"}' | jq

# Recent devices
curl -s -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ latestDevices(withinMinutes: 5) { ip mac } }"}' | jq

# Schema introspection
curl -s "http://localhost:4000/graphql?query={__schema{queryType{fields{name}}}}"
```

## How it works

1. Sends ARP request packets to every IP in the configured subnet
2. Listens for ARP replies for 5 seconds
3. Upserts discovered devices into SurrealDB, tracking IP changes and discovery events
4. Repeats at the configured interval
5. Serves device data via GraphQL

## Database

Uses SurrealDB with RocksDB storage. Tables:

- **device** — current device state (ip, mac, alias, vendor, first_seen, last_seen)
- **event** — history events (discovered, ip_changed)
