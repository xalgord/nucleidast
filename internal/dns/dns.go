package dns

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"nucleidast/internal/config"
	"nucleidast/internal/utils"
)

// Resolve takes a list of subdomains and returns only the ones that resolve via dnsx
func Resolve(cfg *config.Config, subdomains []string, outputDir string) ([]string, error) {
	if len(subdomains) == 0 {
		return nil, nil
	}

	if !utils.ToolExists("dnsx") {
		return nil, fmt.Errorf("dnsx not found in PATH")
	}

	utils.LogInfo("Running dnsx on %d subdomains...", len(subdomains))
	start := time.Now()

	// Write subdomains to a temp file for dnsx input
	inputFile := fmt.Sprintf("%s/dnsx_input.txt", outputDir)
	if err := utils.WriteLinesToFile(inputFile, subdomains); err != nil {
		return nil, fmt.Errorf("failed to write dnsx input: %w", err)
	}

	args := []string{
		"-l", inputFile,
		"-silent",
		"-t", fmt.Sprintf("%d", cfg.DNS.Threads),
	}

	cmd := exec.CommandContext(context.Background(), "dnsx", args...)
	utils.LogDebug("Running: dnsx %s", strings.Join(args, " "))

	output, err := cmd.Output()
	if err != nil {
		// Try to use partial output
		if len(output) == 0 {
			return nil, fmt.Errorf("dnsx failed: %v", err)
		}
	}

	var results []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			results = append(results, line)
		}
	}

	results = utils.DeduplicateLines(results)

	// Write results
	outputFile := fmt.Sprintf("%s/live_subdomains.txt", outputDir)
	if err := utils.WriteLinesToFile(outputFile, results); err != nil {
		utils.LogWarn("Failed to write live subdomains file: %v", err)
	}

	// Cleanup temp file
	os.Remove(inputFile)

	elapsed := time.Since(start).Round(time.Second)
	utils.LogSuccess("dnsx resolved %d/%d live subdomains in %s", len(results), len(subdomains), elapsed)

	return results, nil
}
