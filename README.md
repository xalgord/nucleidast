<p align="center">
  <h1 align="center">NucleiDAST</h1>
  <p align="center">Automated DAST Scanning Pipeline built in Go</p>
</p>

<p align="center">
  <a href="https://github.com/xalgord/nucleidast/releases"><img src="https://img.shields.io/github/v/release/xalgord/nucleidast?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://github.com/xalgord/nucleidast/blob/master/LICENSE"><img src="https://img.shields.io/github/license/xalgord/nucleidast?style=flat-square" alt="License"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/made%20with-Go-00ADD8?style=flat-square" alt="Go"></a>
</p>

---

## Overview

NucleiDAST orchestrates an end-to-end **Dynamic Application Security Testing** pipeline — from subdomain discovery to vulnerability reporting — with parallel execution at every stage.

## Pipeline

```
┌──────────┐    ┌───────────────────┐    ┌──────────┐    ┌─────────────────┐    ┌──────────┐    ┌──────────────┐    ┌─────────┐
│  Targets │───▶│  Subdomain Enum   │───▶│   dnsx   │───▶│   URL Enum      │───▶│   uro    │───▶│  Nuclei DAST │───▶│ Discord │
│          │    │  (parallel)       │    │          │    │  (parallel)     │    │  dedup   │    │              │    │ Webhook │
└──────────┘    │ • subfinder       │    └──────────┘    │ • waymore       │    └──────────┘    └──────────────┘    └─────────┘
                │ • findomain       │                    │ • gau           │
                │ • assetfinder     │                    │ • paramspider   │
                └───────────────────┘                    │ • gospider      │
                                                        └─────────────────┘
```

## Features

- 🔍 **Subdomain Enumeration** — subfinder, findomain, assetfinder running in parallel
- 🌐 **DNS Resolution** — dnsx filters to only live/resolvable hosts
- 🔗 **URL Enumeration** — waymore, gau, paramspider, gospider running in parallel (Python venv-aware)
- 🧹 **URL Deduplication** — [uro](https://github.com/s0md3v/uro) removes similar/redundant URLs before scanning
- 🎯 **Vulnerability Scanning** — Nuclei DAST with configurable severity & rate limits
- 📢 **Discord Reporting** — Rich embeds with color-coded severity, streamed in real-time
- ⚡ **Parallel Execution** — Multiple targets processed concurrently with configurable limits
- 🛡️ **Graceful Degradation** — Missing tools are skipped with warnings, pipeline continues
- ⚙️ **YAML Config** — Full control over every tool, rate limit, severity filter, and webhook

## Installation

### Using Go Install

```bash
go install github.com/xalgord/nucleidast@latest
```

### From Source

```bash
git clone https://github.com/xalgord/nucleidast.git
cd nucleidast
go build -o nucleidast .
```

### From Release

Download the latest binary from the [Releases](https://github.com/xalgord/nucleidast/releases) page.

## Usage

```bash
# Single target
sudo ./nucleidast -t example.com

# Multiple targets from file
sudo ./nucleidast -l targets.txt

# Custom config & verbose output
sudo ./nucleidast -t example.com -c /path/to/config.yaml -v

# Custom output directory
sudo ./nucleidast -t example.com -o /tmp/results
```

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--target` | `-t` | Single target domain | — |
| `--list` | `-l` | File with list of targets (one per line) | — |
| `--config` | `-c` | Path to config file | `~/.config/nucleidast/config.yaml` |
| `--output` | `-o` | Output directory | `./output` |
| `--verbose` | `-v` | Enable verbose/debug output | `false` |

> **Note:** Run as root (`sudo`) to ensure all security tools are accessible.

## Configuration

Config is read from `~/.config/nucleidast/config.yaml` by default. A sample config is included in the repo.

```yaml
# Discord Webhook Reporting
discord:
  webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK"
  notify_on:
    - critical
    - high
    - medium
  batch_size: 10

# Subdomain Enumeration
subdomain:
  threads: 100
  use_subfinder: true
  use_findomain: true
  use_assetfinder: true

# DNS Resolution
dns:
  threads: 100

# URL Enumeration
urlenum:
  use_waymore: true
  use_gau: true
  use_paramspider: true
  use_gospider: true
  python_venv: "~/venv/bin/activate"

# Nuclei DAST Scanner
nuclei:
  severity: "critical,high,medium"
  rate_limit: 5
  concurrency: 5
  dast: true
  dashboard: true
  extra_args: []

# General
output_dir: "./output"
max_concurrent_targets: 3
verbose: false
```

## Output Structure

```
output/
└── example.com/
    ├── subdomains.txt          # All discovered subdomains
    ├── live_subdomains.txt     # DNS-resolved live subdomains
    ├── urls_raw.txt            # All enumerated URLs (before dedup)
    ├── urls.txt                # Deduplicated URLs (after uro)
    └── nuclei_results.jsonl    # Nuclei findings in JSONL format
```

## Required Tools

| Tool | Type | Install |
|------|------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Go | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [findomain](https://github.com/Findomain/Findomain) | Binary | [GitHub Releases](https://github.com/Findomain/Findomain/releases) |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Go | `go install github.com/tomnomnom/assetfinder@latest` |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Go | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| [gau](https://github.com/lc/gau) | Go | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [gospider](https://github.com/jaeles-project/gospider) | Go | `go install github.com/jaeles-project/gospider@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Go | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [waymore](https://github.com/xnl-h4ck3r/waymore) | Python | `pip install waymore` |
| [paramspider](https://github.com/devanshbatham/ParamSpider) | Python | `pip install paramspider` |
| [uro](https://github.com/s0md3v/uro) | Python | `pip install uro` |

> Python tools (waymore, paramspider, uro) require a virtual environment. Set the path in `config.yaml` under `urlenum.python_venv`.

## Discord Notifications

Findings are sent as rich Discord embeds with:
- 🔴 **Critical** — Red embed
- 🟠 **High** — Orange embed
- 🟡 **Medium** — Yellow embed  
- 🔵 **Low** — Cyan embed

Each finding includes: template name, severity, matched URL, extracted results, and cURL command. A summary embed is sent at the end of each scan.

## License

MIT
