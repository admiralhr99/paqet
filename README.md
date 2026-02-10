# paqet - transport over raw packets

[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`paqet` is a bidirectional packet level proxy built using raw sockets. It forwards traffic from a local client to a remote server, bypassing the host operating system's TCP/IP stack, using KCP for secure, reliable transport.

> **⚠️ Development Status Notice**
>
> This project is in **active development**. APIs, configuration formats, and interfaces may change without notice. Use with caution in production environments.

## How It Works

`paqet` supports multiple transport modes for different network environments:

| Mode | Description | Best For |
|------|-------------|----------|
| **pcap** (default) | Raw packet injection via libpcap, bypasses kernel TCP stack entirely | Standard VPS, local networks |
| **tcp** | Uses kernel TCP with KCP framed over it | Restrictive hypervisors (Arvan, OpenStack) — **guaranteed to work** |
| **tun** | Writes crafted IP packets to a TUN device, kernel handles routing | OpenStack anti-spoofing environments |
| **nfqueue** | Real kernel TCP + NFQUEUE packet interception for header modification | Advanced: real TCP state + full packet control |

```
[Your App] <------> [paqet Client] <===== Raw TCP Packet =====> [paqet Server] <------> [Target Server]
(e.g. curl)        (localhost:1080)        (Internet)          (Public IP:PORT)     (e.g. https://httpbin.org)
```

### Transport Mode Details

**pcap** (default): Captures packets using `pcap` and injects crafted TCP packets containing encrypted transport data. KCP provides reliable, encrypted communication optimized for high-loss networks. This bypasses the OS kernel's TCP/IP stack completely.

**tcp**: Uses the kernel's real TCP stack (`net.Dial`/`net.Listen`). KCP packets are length-prefix framed over the TCP stream. The kernel handles the 3-way handshake and all TCP state, which satisfies hypervisor-level TCP tracking (e.g., Arvan Cloud/OpenStack). DPI evasion is applied at the application layer (entropy wrapping on first frame) and optionally via iptables fragmentation.

**tun**: Creates a TUN device and writes crafted IP+TCP packets into it. The kernel routes the packets through the real interface, adding proper Ethernet headers. This satisfies hypervisors that validate MAC/IP spoofing. All evasion modules (entropy, probe resistance, TCP fingerprint) work since IP+TCP headers are still manually crafted.

**nfqueue**: Combines real kernel TCP connections with NFQUEUE (netfilter queue) packet interception. The kernel performs the TCP handshake normally, then NFQUEUE captures packets after kernel processing for DPI evasion modifications before they hit the wire. Requires iptables rules to direct packets to the queue.

## Getting Started

### Prerequisites

- **pcap mode:** `libpcap` development libraries must be installed.
  - **Debian/Ubuntu:** `sudo apt-get install libpcap-dev`
  - **RHEL/CentOS/Fedora:** `sudo yum install libpcap-devel`
  - **macOS:** Comes pre-installed with Xcode Command Line Tools. Install with `xcode-select --install`
  - **Windows:** Install Npcap. Download from [npcap.com](https://npcap.com/).
- **tcp mode:** No additional dependencies.
- **tun mode:** Linux only. Requires `/dev/net/tun` and `ip` command.
- **nfqueue mode:** Linux only. Requires `iptables` and `CAP_NET_ADMIN`.

### 1. Download a Release

Download the pre-compiled binary for your client and server operating systems from the project's **Releases page**.

You will also need the configuration files from the `example/` directory.

### 2. Configure the Connection

#### Transport Mode Selection

Add the `mode` field to the `network` section of your config. If omitted, it defaults to `"pcap"` (existing behavior).

```yaml
network:
  mode: "tcp"    # "pcap" (default), "tcp", "tun", "nfqueue"
```

#### Finding Your Network Details (pcap & tun modes)

For `pcap` and `tun` modes, you need your network interface name, local IP, and (for pcap) the MAC address of your gateway.

**On Linux:**

1.  **Find Interface and Local IP:** Run `ip a`. Look for your primary network card (e.g., `eth0`, `ens3`). Its IP address is listed under `inet`.
2.  **Find Gateway MAC (pcap mode only):**
    - First, find your gateway's IP: `ip r | grep default`
    - Then, find its MAC address with `arp -n <gateway_ip>` (e.g., `arp -n 192.168.1.1`).

**On macOS:**

1.  **Find Interface and Local IP:** Run `ifconfig`. Look for your primary interface (e.g., `en0`). Its IP is listed under `inet`.
2.  **Find Gateway MAC (pcap mode only):**
    - First, find your gateway's IP: `netstat -rn | grep default`
    - Then, find its MAC address with `arp -n <gateway_ip>` (e.g., `arp -n 192.168.1.1`).

**On Windows:**

1. **Find Interface and Local IP:** Run `ipconfig /all` and note your active network adapter (Ethernet or Wi-Fi):
   - Its **IP Address**
   - The **Gateway IP Address**
2. **Find Interface device GUID:** Windows requires the Npcap device GUID. In PowerShell, run `Get-NetAdapter | Select-Object Name, InterfaceGuid`. Note the **Name** and **InterfaceGuid** of your active network interface, and format the GUID as `\Device\NPF_{GUID}`.
3. **Find Gateway MAC Address:** Run: `arp -a <gateway_ip>`. Note the MAC address for the gateway.

> **Note:** For `tcp` and `nfqueue` modes, you do **not** need interface, IP, or MAC configuration — the kernel handles all of this automatically.

#### Example Configurations

##### pcap mode — Client (default, same as before)

```yaml
role: "client"
log:
  level: "info"
socks5:
  - listen: "127.0.0.1:1080"
network:
  mode: "pcap"   # or omit — pcap is the default
  interface: "en0"
  ipv4:
    addr: "192.168.1.100:0"
    router_mac: "aa:bb:cc:dd:ee:ff"
server:
  addr: "10.0.0.100:9999"
transport:
  protocol: "kcp"
  kcp:
    block: "aes"
    key: "your-secret-key-here"
```

##### tcp mode — Client (for Arvan/OpenStack VPS)

```yaml
role: "client"
log:
  level: "debug"
socks5:
  - listen: "127.0.0.1:1080"
network:
  mode: "tcp"
server:
  addr: "45.140.43.136:11000"
transport:
  protocol: "kcp"
  kcp:
    mode: "fast"
    key: "your-secret-key-here"
evasion:
  entropy_mode: "tls"
  sni: "www.microsoft.com"
  auth_secret: "your-shared-secret-minimum-16-chars"
  fallback_url: "https://www.microsoft.com"
```

##### tcp mode — Server

```yaml
role: "server"
log:
  level: "debug"
listen:
  addr: ":11000"
network:
  mode: "tcp"
transport:
  protocol: "kcp"
  kcp:
    mode: "fast"
    key: "your-secret-key-here"
evasion:
  entropy_mode: "tls"
  sni: "www.microsoft.com"
  auth_secret: "your-shared-secret-minimum-16-chars"
  fallback_url: "https://www.microsoft.com"
```

##### tun mode — Client

```yaml
role: "client"
log:
  level: "debug"
socks5:
  - listen: "127.0.0.1:1080"
network:
  mode: "tun"
  interface: "eth0"
  ipv4:
    addr: "185.206.94.12:0"
server:
  addr: "45.140.43.136:11000"
transport:
  protocol: "kcp"
  kcp:
    mode: "fast"
    key: "your-secret-key-here"
evasion:
  entropy_mode: "tls"
  sni: "www.microsoft.com"
  auth_secret: "your-shared-secret-minimum-16-chars"
```

##### nfqueue mode — Client

```yaml
role: "client"
log:
  level: "debug"
socks5:
  - listen: "127.0.0.1:1080"
network:
  mode: "nfqueue"
  nfqueue:
    out_queue: 100
    in_queue: 101
server:
  addr: "45.140.43.136:11000"
transport:
  protocol: "kcp"
  kcp:
    mode: "fast"
    key: "your-secret-key-here"
evasion:
  entropy_mode: "tls"
  sni: "www.microsoft.com"
  auth_secret: "your-shared-secret-minimum-16-chars"
```

#### Critical Firewall Configuration (pcap & tun modes)

For `pcap` and `tun` modes, the OS kernel can see incoming packets and generate TCP RST packets since it has no knowledge of the connection.

You **must** configure `iptables` on the server to prevent the kernel from interfering.

> **Note:** `tcp` and `nfqueue` modes do **not** need RST suppression — the kernel manages TCP state naturally.

> **⚠️ Important - Avoid Standard Ports**
>
> Do not use ports 80, 443, or any other standard ports, because iptables rules can also affect outgoing connections from the server.

Run these commands as root on your server:

```bash
# Replace <PORT> with your server listen port (e.g., 9999)

# 1. Bypass connection tracking (conntrack) for the connection port.
sudo iptables -t raw -A PREROUTING -p tcp --dport <PORT> -j NOTRACK
sudo iptables -t raw -A OUTPUT -p tcp --sport <PORT> -j NOTRACK

# 2. Prevent the kernel from sending TCP RST packets.
sudo iptables -t mangle -A OUTPUT -p tcp --sport <PORT> --tcp-flags RST RST -j DROP

# To make rules persistent across reboots:
# Debian/Ubuntu: sudo iptables-save > /etc/iptables/rules.v4
# RHEL/CentOS: sudo service iptables save
```

#### NFQUEUE Setup (nfqueue mode only)

Before running paqet in `nfqueue` mode, set up iptables rules to direct packets to the queue:

```bash
# Use the provided script:
sudo ./scripts/nfqueue-setup.sh <server_ip> <server_port> [out_queue] [in_queue]

# Example:
sudo ./scripts/nfqueue-setup.sh 45.140.43.136 11000 100 101
```

Or manually:

```bash
iptables -A OUTPUT -p tcp -d <SERVER_IP> --dport <PORT> -j NFQUEUE --queue-num 100
iptables -A INPUT -p tcp -s <SERVER_IP> --sport <PORT> -j NFQUEUE --queue-num 101
```

#### DPI Evasion via iptables (tcp mode)

For `tcp` mode, since you can't craft raw packets, DPI evasion for the initial handshake can be done via iptables fragmentation:

```bash
# Use the provided script:
sudo ./scripts/dpi-evasion-iptables.sh <server_ip> <server_port>

# Example:
sudo ./scripts/dpi-evasion-iptables.sh 45.140.43.136 11000
```

### 3. Run `paqet`

Make the downloaded binary executable (`chmod +x ./paqet_linux_amd64`). You will need root privileges for all modes.

**On the Server:**

```bash
sudo ./paqet_linux_amd64 run -c config.yaml
```

**On the Client:**

```bash
sudo ./paqet_darwin_arm64 run -c config.yaml
```

### 4. Test the Connection

Once the client and server are running, test the SOCKS5 proxy:

```bash
# Test with curl using the SOCKS5 proxy
curl -v https://httpbin.org/ip --proxy socks5h://127.0.0.1:1080
```

This request will be proxied over the configured transport to the server, and then forwarded to the target. The output should show your server's public IP address, confirming the connection is working.

## Command-Line Usage

`paqet` is a multi-command application. The primary command is `run`, which starts the proxy, but several utility commands are included to help with configuration and debugging.

The general syntax is:

```bash
sudo ./paqet <command> [arguments]
```

| Command   | Description                                                                      |
| :-------- | :------------------------------------------------------------------------------- |
| `run`     | Starts the `paqet` client or server proxy. This is the main operational command. |
| `secret`  | Generates a new, cryptographically secure secret key.                            |
| `ping`    | Sends a single test packet to the server to verify connectivity .                |
| `dump`    | A diagnostic tool similar to `tcpdump` that captures and decodes packets.        |
| `version` | Prints the application's version information.                                    |

## Configuration Reference

paqet uses unified YAML configuration for client and server. The `role` field must be explicitly set to either `"client"` or `"server"`.

### Transport Modes

| Field | Values | Default | Description |
|-------|--------|---------|-------------|
| `network.mode` | `pcap`, `tcp`, `tun`, `nfqueue` | `pcap` | Transport backend selection |

### Evasion Configuration

| Field | Values | Default | Description |
|-------|--------|---------|-------------|
| `evasion.entropy_mode` | `tls`, `ascii`, `auto`, `none` | `none` | First-packet camouflage mode |
| `evasion.sni` | hostname string | `www.microsoft.com` | SNI for TLS ClientHello wrapping |
| `evasion.auth_secret` | string (min 16 chars) | — | HMAC-SHA256 auth key (required when evasion enabled) |
| `evasion.fallback_url` | URL string | `https://www.microsoft.com` | Fallback website for probe resistance (server only) |

### NFQUEUE Configuration

| Field | Values | Default | Description |
|-------|--------|---------|-------------|
| `network.nfqueue.out_queue` | uint16 | `100` | Queue number for outgoing packets |
| `network.nfqueue.in_queue` | uint16 | `101` | Queue number for incoming packets |

### Encryption Modes

The `transport.kcp.block` parameter determines the encryption method.

⚠️ **Warning:** `none` and `null` modes disable authentication, anyone with your server IP and port can connect.

- **`none`** - Plaintext with protocol header (protocol-compatible)
- **`null`** - Raw data, no header (highest performance, least secure)

### TCP Flag Cycling (pcap & tun modes)

The `network.tcp.local_flag` and `network.tcp.remote_flag` arrays cycle through flag combinations to vary traffic patterns. Common patterns: `["PA"]` (standard data), `["S"]` (connection setup), `["A"]` (acknowledgment).

> **Note:** TCP flag configuration has no effect in `tcp` and `nfqueue` modes since the kernel manages TCP flags.

# Architecture & Security Model

### Transport Mode Architecture

```
                     ┌─────────────────┐
                     │   KCP Protocol   │
                     │  (encrypted ARQ) │
                     └────────┬─────────┘
                              │
                    ┌─────────▼──────────┐
                    │  net.PacketConn     │
                    │  (factory selects)  │
                    └─────────┬──────────┘
                              │
        ┌─────────┬───────────┼───────────┬──────────┐
        │         │           │           │          │
   ┌────▼───┐ ┌───▼───┐ ┌────▼────┐ ┌────▼─────┐
   │  pcap  │ │  tcp  │ │   tun   │ │ nfqueue  │
   │ inject │ │ kernel│ │ device  │ │ intercept│
   └────┬───┘ └───┬───┘ └────┬────┘ └────┬─────┘
        │         │           │           │
        ▼         ▼           ▼           ▼
      Wire      Wire        Wire        Wire
```

### The `pcap` Approach and Firewall Bypass

Understanding why standard firewalls are bypassed is key to using this tool securely.

A normal application uses the OS's TCP/IP stack. When a packet arrives, it travels up the stack where `netfilter` (the backend for `ufw`/`firewalld`) inspects it. If a firewall rule blocks the port, the packet is dropped and never reaches the application.

```
      +------------------------+
      |   Normal Application   |  <-- Data is received here
      +------------------------+
                   ^
      +------------------------+
      |    OS TCP/IP Stack     |  <-- Firewall (netfilter) runs here
      |  (Connection Tracking) |
      +------------------------+
                   ^
      +------------------------+
      |     Network Driver     |
      +------------------------+
```

`paqet` uses `pcap` to hook in at a much lower level. It requests a copy of every packet directly from the network driver, before the main OS TCP/IP stack and firewall get to process it.

```
      +------------------------+
      |    paqet Application   |  <-- Gets a packet copy immediately
      +------------------------+
              ^       \
 (pcap copy) /         \  (Original packet continues up)
            /           v
      +------------------------+
      |     OS TCP/IP Stack    |  <-- Firewall drops the original packet,
      |  (Connection Tracking) |      but paqet already has its copy.
      +------------------------+
                  ^
      +------------------------+
      |     Network Driver     |
      +------------------------+
```

This means a rule like `ufw deny <PORT>` will have no effect on the proxy's operation, as `paqet` receives and processes the packet before `ufw` can block it.

> **Note:** `tcp` and `nfqueue` modes use the kernel TCP stack and **do** respect standard firewall rules. Make sure the configured port is allowed through your firewall.

## Troubleshooting

1.  **Permission Denied:** Ensure you are running with `sudo`.
2.  **Connection Times Out:**
    - **Transport Configuration Mismatch:**
      - **KCP**: Ensure `transport.kcp.key` is exactly identical on client and server
      - **Mode**: Ensure `network.mode` matches on client and server
    - **`iptables` Rules (pcap/tun):** Did you apply the firewall rules on the server?
    - **NFQUEUE rules (nfqueue):** Did you run `scripts/nfqueue-setup.sh`?
    - **Incorrect Network Details (pcap/tun):** Double-check all IPs, MAC addresses, and interface names.
    - **Cloud Provider Firewalls:** Ensure your cloud provider's security group allows TCP traffic on your port.
    - **Hypervisor Blocking (pcap mode):** If on Arvan/OpenStack, switch to `mode: "tcp"`.
3.  **Arvan VPS not working:** Arvan Cloud's hypervisor drops pcap-injected packets. Use `mode: "tcp"` which is guaranteed to work.
4.  **Use `ping` and `dump`:** Use `paqet ping -c config.yaml` to test the connection. Use `paqet dump -p <PORT>` on the server to see if packets are arriving.

## Acknowledgments

This work draws inspiration from the research and implementation in the [gfw_resist_tcp_proxy](https://github.com/GFW-knocker/gfw_resist_tcp_proxy) project by GFW-knocker, which explored the use of raw sockets to circumvent certain forms of network filtering. This project serves as a Go-based exploration of those concepts.

- Uses [pcap](https://github.com/the-tcpdump-group/libpcap) for low-level packet capture and injection
- Uses [gopacket](https://github.com/gopacket/gopacket) for raw packet crafting and decoding
- Uses [kcp-go](https://github.com/xtaci/kcp-go) for reliable transport with encryption
- Uses [smux](https://github.com/xtaci/smux) for connection multiplexing

## License

This project is licensed under the MIT License. See the see [LICENSE](LICENSE) file for details.
