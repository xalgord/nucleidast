package urlenum

import (
	"context"
	"fmt"
	"time"

	"github.com/xalgord/nucleidast/internal/config"
	"github.com/xalgord/nucleidast/internal/utils"
)

// DeduplicateWithUro runs uro to filter out similar/redundant URLs
// Input: raw URLs file, Output: filtered URLs file
func DeduplicateWithUro(cfg *config.Config, inputFile, outputFile string) ([]string, error) {
	utils.LogInfo("Running uro for URL deduplication...")
	start := time.Now()

	venvPath := cfg.URLEnum.PythonVenv

	shellCmd := fmt.Sprintf("source %q && uro -i %q -o %q",
		venvPath, inputFile, outputFile)

	_, err := utils.RunShellCommand(context.Background(), shellCmd)
	if err != nil {
		return nil, fmt.Errorf("uro execution failed: %v", err)
	}

	lines, err := utils.ReadLinesFromFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read uro output: %v", err)
	}

	elapsed := time.Since(start).Round(time.Second)
	utils.LogSuccess("uro deduplication complete: %d unique URLs in %s", len(lines), elapsed)

	return lines, nil
}
