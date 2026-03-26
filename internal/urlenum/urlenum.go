package urlenum

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/xalgord/nucleidast/internal/config"
	"github.com/xalgord/nucleidast/internal/utils"
)

// Enumerate runs all enabled URL enumeration tools in parallel
// and returns a deduplicated list of URLs
func Enumerate(cfg *config.Config, domain string, liveSubdomains []string, outputDir string) []string {
	utils.LogInfo("Starting URL enumeration for %s", domain)
	start := time.Now()

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		allURLs []string
	)

	venvActivate := cfg.URLEnum.PythonVenv

	// Waymore (runs per domain)
	if cfg.URLEnum.UseWaymore {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls, err := runWaymore(domain, outputDir, venvActivate)
			if err != nil {
				utils.LogWarn("waymore failed for %s: %v", domain, err)
				return
			}
			utils.LogSuccess("waymore found %d URLs for %s", len(urls), domain)
			mu.Lock()
			allURLs = append(allURLs, urls...)
			mu.Unlock()
		}()
	}

	// Gau (runs per domain with --subs to include subdomains)
	if cfg.URLEnum.UseGau {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls, err := runGau(domain)
			if err != nil {
				utils.LogWarn("gau failed for %s: %v", domain, err)
				return
			}
			utils.LogSuccess("gau found %d URLs for %s", len(urls), domain)
			mu.Lock()
			allURLs = append(allURLs, urls...)
			mu.Unlock()
		}()
	}

	// Paramspider (runs per domain)
	if cfg.URLEnum.UseParamspider {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls, err := runParamspider(domain, venvActivate)
			if err != nil {
				utils.LogWarn("paramspider failed for %s: %v", domain, err)
				return
			}
			utils.LogSuccess("paramspider found %d URLs for %s", len(urls), domain)
			mu.Lock()
			allURLs = append(allURLs, urls...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	deduped := utils.DeduplicateLines(allURLs)
	elapsed := time.Since(start).Round(time.Second)
	utils.LogSuccess("URL enumeration complete for %s: %d unique URLs in %s", domain, len(deduped), elapsed)

	return deduped
}

func runWaymore(domain, outputDir, venvPath string) ([]string, error) {
	outFile := fmt.Sprintf("%s/waymore_%s.txt", outputDir, domain)

	shellCmd := fmt.Sprintf("source %s && waymore -i %s -mode U -oU %s 2>/dev/null",
		venvPath, domain, outFile)

	_, err := utils.RunShellCommand(context.Background(), shellCmd)
	if err != nil {
		return nil, fmt.Errorf("waymore execution failed: %v", err)
	}

	// Read output file
	if _, statErr := os.Stat(outFile); statErr != nil {
		return nil, fmt.Errorf("waymore output file not found")
	}

	lines, err := utils.ReadLinesFromFile(outFile)
	if err != nil {
		return nil, err
	}

	return lines, nil
}

func runGau(domain string) ([]string, error) {
	// Use full path to avoid shell alias conflicts
	gauPath := ""
	for _, p := range []string{"/home/vulture/go/bin/gau", "/usr/local/bin/gau", "/usr/bin/gau"} {
		if _, err := os.Stat(p); err == nil {
			gauPath = p
			break
		}
	}

	if gauPath == "" {
		if !utils.ToolExists("gau") {
			return nil, fmt.Errorf("gau not found in PATH")
		}
		gauPath = "gau"
	}

	return utils.RunCommand(context.Background(), gauPath, domain, "--subs")
}

func runParamspider(domain, venvPath string) ([]string, error) {
	shellCmd := fmt.Sprintf("source %s && paramspider -d %q -s 2>/dev/null",
		venvPath, domain)

	lines, err := utils.RunShellCommand(context.Background(), shellCmd)
	if err != nil {
		return nil, fmt.Errorf("paramspider execution failed: %v", err)
	}

	// Paramspider also writes to output/ directory, try to read from there
	possibleFiles := []string{
		fmt.Sprintf("output/%s.txt", domain),
		fmt.Sprintf("results/%s.txt", domain),
	}

	for _, f := range possibleFiles {
		if _, statErr := os.Stat(f); statErr == nil {
			fileLines, err := utils.ReadLinesFromFile(f)
			if err == nil {
				lines = append(lines, fileLines...)
			}
		}
	}

	return lines, nil
}
