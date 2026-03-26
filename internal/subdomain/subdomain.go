package subdomain

import (
	"context"
	"fmt"
	"sync"
	"time"

	"nucleidast/internal/config"
	"nucleidast/internal/utils"
)

// Enumerate runs all enabled subdomain enumeration tools in parallel
// and returns a deduplicated list of subdomains
func Enumerate(cfg *config.Config, domain string) []string {
	utils.LogInfo("Starting subdomain enumeration for %s", domain)
	start := time.Now()

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		allSubs []string
	)

	// Subfinder
	if cfg.Subdomain.UseSubfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := runSubfinder(domain, cfg.Subdomain.Threads)
			if err != nil {
				utils.LogWarn("subfinder failed for %s: %v", domain, err)
				return
			}
			utils.LogSuccess("subfinder found %d subdomains for %s", len(subs), domain)
			mu.Lock()
			allSubs = append(allSubs, subs...)
			mu.Unlock()
		}()
	}

	// Findomain
	if cfg.Subdomain.UseFindomain {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := runFindomain(domain)
			if err != nil {
				utils.LogWarn("findomain failed for %s: %v", domain, err)
				return
			}
			utils.LogSuccess("findomain found %d subdomains for %s", len(subs), domain)
			mu.Lock()
			allSubs = append(allSubs, subs...)
			mu.Unlock()
		}()
	}

	// Assetfinder
	if cfg.Subdomain.UseAssetfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := runAssetfinder(domain)
			if err != nil {
				utils.LogWarn("assetfinder failed for %s: %v", domain, err)
				return
			}
			utils.LogSuccess("assetfinder found %d subdomains for %s", len(subs), domain)
			mu.Lock()
			allSubs = append(allSubs, subs...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	deduped := utils.DeduplicateLines(allSubs)
	elapsed := time.Since(start).Round(time.Second)
	utils.LogSuccess("Subdomain enumeration complete for %s: %d unique subdomains in %s", domain, len(deduped), elapsed)

	return deduped
}

func runSubfinder(domain string, threads int) ([]string, error) {
	if !utils.ToolExists("subfinder") {
		return nil, fmt.Errorf("subfinder not found in PATH")
	}

	args := []string{
		"-d", domain,
		"-all",
		"-recursive",
		"-t", fmt.Sprintf("%d", threads),
		"-silent",
	}

	return utils.RunCommand(context.Background(), "subfinder", args...)
}

func runFindomain(domain string) ([]string, error) {
	if !utils.ToolExists("findomain") {
		return nil, fmt.Errorf("findomain not found in PATH")
	}

	return utils.RunCommand(context.Background(), "findomain", "-t", domain, "-q")
}

func runAssetfinder(domain string) ([]string, error) {
	if !utils.ToolExists("assetfinder") {
		return nil, fmt.Errorf("assetfinder not found in PATH")
	}

	shellCmd := fmt.Sprintf("echo %q | assetfinder --subs-only", domain)
	return utils.RunShellCommand(context.Background(), shellCmd)
}
