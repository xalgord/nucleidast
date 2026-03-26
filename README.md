# NucleiDAST

Automated DAST (Dynamic Application Security Testing) scanning pipeline built in Go.

## Pipeline

```
Targets → Subdomain Enum → DNS Resolution → URL Enum → uro Dedup → Nuclei DAST → Discord
              (parallel)                      (parallel)                          (streaming)
```

## Features

- **Subdomain Enumeration** — subfinder, findomain, assetfinder (parallel)
- **DNS Resolution** — dnsx filters to live hosts
- **URL Enumeration** — waymore, gau, paramspider (parallel, venv-aware)
- **URL Deduplication** — uro removes similar/redundant URLs
- **Vulnerability Scanning** — Nuclei DAST with configurable severity & rate limits
- **Discord Reporting** — Rich embeds streamed in real-time as findings come in
- **Parallel Execution** — Multiple targets processed concurrently
- **Graceful Degradation** — Missing tools are skipped with warnings

## Installation

```bash
go build -o nucleidast .
```

## Usage

```bash
# Single target
sudo ./nucleidast -t example.com

# Multiple targets from file
sudo ./nucleidast -l targets.txt

# Custom config & verbose
sudo ./nucleidast -t example.com -c /path/to/config.yaml -v
```

> **Note:** Run as root (`sudo`) to ensure all security tools are accessible.

## Configuration

Config is read from `~/.config/nucleidast/config.yaml` by default.

```yaml
discord:
  webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK"
  notify_on: [critical, high, medium]

subdomain:
  threads: 100
  use_subfinder: true
  use_findomain: true
  use_assetfinder: true

dns:
  threads: 100

urlenum:
  use_waymore: true
  use_gau: true
  use_paramspider: true
  python_venv: "~/venv/bin/activate"

nuclei:
  severity: "critical,high,medium"
  rate_limit: 5
  concurrency: 5
  dast: true
  dashboard: true

output_dir: "./output"
max_concurrent_targets: 3
```

## Required Tools

| Tool | Install |
|------|---------|
| subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| findomain | [GitHub Releases](https://github.com/Findomain/Findomain) |
| assetfinder | `go install github.com/tomnomnom/assetfinder@latest` |
| dnsx | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| waymore | `pip install waymore` |
| paramspider | `pip install paramspider` |
| uro | `pip install uro` |
