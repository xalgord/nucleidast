package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"nucleidast/internal/config"
	"nucleidast/internal/utils"
)

// Finding represents a single Nuclei vulnerability finding
type Finding struct {
	Template         string   `json:"template-id"`
	TemplateURL      string   `json:"template-url"`
	MatchedAt        string   `json:"matched-at"`
	Host             string   `json:"host"`
	IP               string   `json:"ip"`
	Timestamp        string   `json:"timestamp"`
	CURLCommand      string   `json:"curl-command"`
	Type             string   `json:"type"`
	ExtractedResults []string `json:"extracted-results"`
	MatcherName      string   `json:"matcher-name"`

	// Nuclei nests name/severity/description under "info"
	Info struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		Reference   []string `json:"reference"`
	} `json:"info"`

	// Convenience accessors (populated after parsing)
	Name        string `json:"-"`
	Severity    string `json:"-"`
	Description string `json:"-"`
}

// Scan runs nuclei DAST scan and streams findings to the provided channel
func Scan(cfg *config.Config, urlsFile string, outputDir string, findings chan<- Finding) error {
	defer close(findings)

	if !utils.ToolExists("nuclei") {
		return fmt.Errorf("nuclei not found in PATH")
	}

	utils.LogInfo("Starting Nuclei DAST scan on %s", urlsFile)
	start := time.Now()

	outputFile := fmt.Sprintf("%s/nuclei_results.jsonl", outputDir)

	args := []string{
		"-l", urlsFile,
		"-s", cfg.Nuclei.Severity,
		"-rl", fmt.Sprintf("%d", cfg.Nuclei.RateLimit),
		"-c", fmt.Sprintf("%d", cfg.Nuclei.Concurrency),
		"-jsonl",
		"-o", outputFile,
	}

	if cfg.Nuclei.DAST {
		args = append(args, "-dast")
	}

	if cfg.Nuclei.Dashboard {
		args = append(args, "-dashboard")
	}

	for _, extra := range cfg.Nuclei.ExtraArgs {
		args = append(args, extra)
	}

	cmd := exec.CommandContext(context.Background(), "nuclei", args...)
	utils.LogDebug("Running: nuclei %s", strings.Join(args, " "))

	// Get stdout pipe to stream findings as they come
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Suppress stderr noise
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nuclei: %w", err)
	}

	// Read output line by line and parse JSONL
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	findingCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var finding Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			utils.LogDebug("Failed to parse nuclei output line: %s", line)
			continue
		}

		// Populate convenience fields from nested Info struct
		finding.Severity = finding.Info.Severity
		finding.Name = finding.Info.Name
		finding.Description = finding.Info.Description

		findingCount++
		utils.LogInfo("[%s] %s — %s",
			severityColor(finding.Severity),
			finding.Name,
			finding.MatchedAt)

		// Stream finding to reporter
		findings <- finding
	}

	if err := cmd.Wait(); err != nil {
		// Non-zero exit is common for nuclei, not necessarily an error
		utils.LogDebug("nuclei exited with: %v", err)
	}

	elapsed := time.Since(start).Round(time.Second)
	utils.LogSuccess("Nuclei scan complete: %d findings in %s", findingCount, elapsed)

	return nil
}

func severityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return utils.ColorRed + utils.ColorBold + "CRITICAL" + utils.ColorReset
	case "high":
		return utils.ColorRed + "HIGH" + utils.ColorReset
	case "medium":
		return utils.ColorYellow + "MEDIUM" + utils.ColorReset
	case "low":
		return utils.ColorCyan + "LOW" + utils.ColorReset
	case "info":
		return utils.ColorGray + "INFO" + utils.ColorReset
	default:
		return severity
	}
}
