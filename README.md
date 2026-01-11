# Sentinel

**Real-time ransomware detection and prevention for Linux servers.**

Sentinel uses entropy analysis, eBPF tracing, and fanotify to detect and stop ransomware before it destroys your files.

## Features

- **Entropy Detection** - Flags files transitioning from low to high entropy (encryption signature)
- **Header Validation** - Detects destroyed file magic bytes
- **Velocity Tracking** - Catches mass encryption (100+ files/minute)
- **Canary Files** - Hidden tripwires that trigger on any access
- **Process Freezing** - SIGSTOP suspicious processes instantly
- **eBPF Tracing** - Kernel-level process context with zero overhead
- **fanotify Gating** - Block writes before damage occurs
- **AIDE Integration** - Periodic baseline integrity checks

## How It Works

```
File Write Attempt
       │
       ▼
┌──────────────┐
│   inotify    │──── "File changed at /home/user/doc.pdf"
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    eBPF      │──── "PID 1847, /tmp/cryptor, UID 1000"
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Entropy    │──── "3.2 → 7.98 = RANSOMWARE"
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  fanotify    │──── BLOCK + Freeze PID + Alert
└──────────────┘
```

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/sentinel.git
cd sentinel

# Build release binary
cargo build --release

# Install (requires root for eBPF)
sudo cp target/release/sentinel /usr/local/bin/
```

### Requirements

- Linux kernel 5.8+ (for eBPF CO-RE)
- Root privileges (for fanotify and eBPF)
- Rust 1.75+ (for building)

## Usage

### Basic Commands

```bash
# Start the daemon
sudo sentinel start

# Watch a directory
sudo sentinel watch /home/user/Documents

# Check status
sudo sentinel status

# View logs
sudo sentinel logs

# Whitelist a process
sudo sentinel whitelist add firefox

# Stop the daemon
sudo sentinel stop
```

### Configuration

```yaml
# /etc/sentinel/config.yaml

watch:
  - /home
  - /var/www
  - /etc

exclude:
  - /tmp
  - "*.log"

whitelist:
  processes:
    - firefox
    - code
    - python3

alerts:
  desktop: true
  webhook: "https://your-webhook-url"

aide:
  enabled: true
  schedule: "0 3 * * *"  # 3 AM daily
```

### ML/AI Server Optimized Config

```yaml
# /etc/sentinel/ml-server.yaml

mode: ml-optimized

exclude:
  - /models/**
  - /datasets/**
  - /checkpoints/**
  - "*.safetensors"
  - "*.gguf"
  - "*.pt"

whitelist:
  processes:
    - python*
    - ollama
    - vllm
```

## Architecture

```
sentinel/
├── src/
│   ├── main.rs           # CLI entry point
│   ├── lib.rs            # Library exports
│   ├── daemon.rs         # Background service
│   ├── watcher/          # File system monitoring
│   │   ├── mod.rs
│   │   ├── inotify.rs    # inotify implementation
│   │   └── fanotify.rs   # fanotify with blocking
│   ├── ebpf/             # Kernel tracing
│   │   ├── mod.rs
│   │   └── tracer.rs     # eBPF program loader
│   ├── detector/         # Threat detection
│   │   ├── mod.rs
│   │   ├── entropy.rs    # Shannon entropy (SIMD)
│   │   ├── header.rs     # Magic byte validation
│   │   ├── velocity.rs   # Rate limiting
│   │   └── canary.rs     # Honeypot files
│   ├── response/         # Threat response
│   │   ├── mod.rs
│   │   ├── freeze.rs     # Process suspension
│   │   └── alert.rs      # Notifications
│   └── config.rs         # Configuration
├── src/ebpf/
│   └── sentinel.bpf.c    # eBPF program (C)
├── configs/
│   ├── default.yaml
│   └── ml-server.yaml
└── tests/
```

## Performance

| Layer | Overhead | Notes |
|:------|:--------:|:------|
| inotify | ~0.001% | Event notification only |
| eBPF | ~0.01% | Kernel-level, near-zero |
| fanotify | ~0.1% | Permission checks |
| Entropy calc | ~0.05% | SIMD accelerated |
| AIDE scan | Variable | Scheduled, excludable |

## Detection Methods

### 1. Entropy Analysis

Normal files have predictable patterns (entropy ~3-5). Encrypted files are indistinguishable from random noise (entropy ~7.9-8.0). Sentinel flags any file transitioning from low to high entropy.

### 2. Header Validation

Ransomware encrypts entire files including headers. A `.docx` that doesn't start with `PK` (ZIP signature) has been encrypted. Sentinel validates magic bytes against file extensions.

### 3. Velocity Detection

Normal users save 1-2 files per minute. Ransomware encrypts 100+ files per minute. Sentinel rate-limits high-entropy writes per process.

### 4. Canary Files

Hidden bait files that no legitimate software touches. Any access is 100% malware. Zero false positives.

## Comparison

| Feature | Sentinel | CrowdStrike | Falco | AIDE |
|:--------|:--------:|:-----------:|:-----:|:----:|
| Entropy detection | Yes | Yes | No | No |
| eBPF tracing | Yes | Yes | Yes | No |
| fanotify blocking | Yes | No | No | No |
| Offline operation | Yes | No | Yes | Yes |
| Open source | Yes | No | Yes | Yes |
| Price | Free | $$$$ | Free | Free |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Security

To report security vulnerabilities, please email security@yourdomain.com instead of opening a public issue.
