package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/xalgord/nucleidast/internal/config"
	"github.com/xalgord/nucleidast/internal/utils"
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
	ScanProfile string `json:"-"` // which scan profile found this
}

// Scan runs a single nuclei scan profile and streams findings to the provided channel.
// NOTE: The caller is responsible for closing the findings channel.
func Scan(profile config.NucleiScanProfile, urlsFile string, outputDir string, findings chan<- Finding) error {
	if !utils.ToolExists("nuclei") {
		return fmt.Errorf("nuclei not found in PATH")
	}

	utils.LogInfo("[%s] Starting scan on %s", profile.Name, urlsFile)
	start := time.Now()

	// Sanitize profile name for filename
	safeName := strings.ReplaceAll(strings.ToLower(profile.Name), " ", "_")
	outputFile := fmt.Sprintf("%s/nuclei_%s.jsonl", outputDir, safeName)

	args := []string{
		"-l", urlsFile,
		"-rl", fmt.Sprintf("%d", profile.RateLimit),
		"-c", fmt.Sprintf("%d", profile.Concurrency),
		"-jsonl",
		"-o", outputFile,
	}

	if profile.Severity != "" {
		args = append(args, "-s", profile.Severity)
	}

	if profile.DAST {
		args = append(args, "-dast")
	}

	if profile.Dashboard {
		args = append(args, "-dashboard")
	}

	if profile.Tags != "" {
		args = append(args, "-tags", profile.Tags)
	}

	for _, tmpl := range profile.Templates {
		args = append(args, "-t", tmpl)
	}

	for _, extra := range profile.ExtraArgs {
		args = append(args, extra)
	}

	cmd := exec.CommandContext(context.Background(), "nuclei", args...)
	utils.LogDebug("[%s] Running: nuclei %s", profile.Name, strings.Join(args, " "))

	// Get stdout pipe to stream findings as they come
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("[%s] failed to create stdout pipe: %w", profile.Name, err)
	}

	// Suppress stderr noise
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("[%s] failed to start nuclei: %w", profile.Name, err)
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
			utils.LogDebug("[%s] Failed to parse nuclei output line: %s", profile.Name, line)
			continue
		}

		// Populate convenience fields from nested Info struct
		finding.Severity = finding.Info.Severity
		finding.Name = finding.Info.Name
		finding.Description = finding.Info.Description
		finding.ScanProfile = profile.Name

		findingCount++
		utils.LogInfo("[%s] [%s] %s — %s",
			profile.Name,
			severityColor(finding.Severity),
			finding.Name,
			finding.MatchedAt)

		// Stream finding to reporter
		findings <- finding
	}

	if err := cmd.Wait(); err != nil {
		// Non-zero exit is common for nuclei, not necessarily an error
		utils.LogDebug("[%s] nuclei exited with: %v", profile.Name, err)
	}

	elapsed := time.Since(start).Round(time.Second)
	utils.LogSuccess("[%s] Scan complete: %d findings in %s", profile.Name, findingCount, elapsed)

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
