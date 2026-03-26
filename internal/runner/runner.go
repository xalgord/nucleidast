package runner

import (
	"fmt"
	"sync"
	"time"

	"nucleidast/internal/config"
	"nucleidast/internal/dns"
	"nucleidast/internal/reporter"
	"nucleidast/internal/scanner"
	"nucleidast/internal/subdomain"
	"nucleidast/internal/urlenum"
	"nucleidast/internal/utils"
)

// Run executes the full DAST pipeline for all targets
func Run(cfg *config.Config, targets []string) error {
	utils.Banner()

	utils.LogInfo("Loaded %d target(s)", len(targets))
	utils.LogInfo("Max concurrent targets: %d", cfg.MaxConcurrentTargets)
	utils.LogInfo("Output directory: %s", cfg.OutputDir)

	if cfg.Discord.WebhookURL == "" {
		utils.LogWarn("Discord webhook not configured — findings will only be saved locally")
	}

	start := time.Now()

	// Semaphore to limit concurrent target processing
	sem := make(chan struct{}, cfg.MaxConcurrentTargets)
	var wg sync.WaitGroup
	errors := make([]error, 0)
	var errorsMu sync.Mutex

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore

		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore

			if err := processDomain(cfg, domain); err != nil {
				utils.LogError("Pipeline failed for %s: %v", domain, err)
				errorsMu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", domain, err))
				errorsMu.Unlock()
			}
		}(target)
	}

	wg.Wait()

	elapsed := time.Since(start).Round(time.Second)
	utils.LogSuccess("All targets processed in %s", elapsed)

	if len(errors) > 0 {
		utils.LogWarn("%d target(s) had errors:", len(errors))
		for _, err := range errors {
			utils.LogError("  → %v", err)
		}
	}

	return nil
}

// processDomain runs the full pipeline for a single domain
func processDomain(cfg *config.Config, domain string) error {
	utils.LogInfo("═══════════════════════════════════════════")
	utils.LogInfo("Processing target: %s", domain)
	utils.LogInfo("═══════════════════════════════════════════")

	// Create output directory for this domain
	domainOutputDir := fmt.Sprintf("%s/%s", cfg.OutputDir, domain)
	if err := utils.EnsureDir(domainOutputDir); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	// ────────────────────────────────────────────
	// Stage 1: Subdomain Enumeration
	// ────────────────────────────────────────────
	utils.LogInfo("▶ Stage 1: Subdomain Enumeration")
	subdomains := subdomain.Enumerate(cfg, domain)

	if len(subdomains) == 0 {
		utils.LogWarn("No subdomains found for %s, using root domain only", domain)
		subdomains = []string{domain}
	}

	// Save subdomains
	subsFile := fmt.Sprintf("%s/subdomains.txt", domainOutputDir)
	if err := utils.WriteLinesToFile(subsFile, subdomains); err != nil {
		utils.LogWarn("Failed to save subdomains file: %v", err)
	}
	utils.LogInfo("Saved %d subdomains to %s", len(subdomains), subsFile)

	// ────────────────────────────────────────────
	// Stage 2: DNS Resolution
	// ────────────────────────────────────────────
	utils.LogInfo("▶ Stage 2: DNS Resolution (dnsx)")
	liveSubdomains, err := dns.Resolve(cfg, subdomains, domainOutputDir)
	if err != nil {
		utils.LogWarn("DNS resolution failed: %v, proceeding with all subdomains", err)
		liveSubdomains = subdomains
	}

	if len(liveSubdomains) == 0 {
		utils.LogWarn("No live subdomains for %s, using root domain", domain)
		liveSubdomains = []string{domain}
	}

	// ────────────────────────────────────────────
	// Stage 3: URL Enumeration
	// ────────────────────────────────────────────
	utils.LogInfo("▶ Stage 3: URL Enumeration")
	urls := urlenum.Enumerate(cfg, domain, liveSubdomains, domainOutputDir)

	if len(urls) == 0 {
		utils.LogWarn("No URLs found for %s, skipping nuclei scan", domain)
		return nil
	}

	// Save raw URLs
	rawURLsFile := fmt.Sprintf("%s/urls_raw.txt", domainOutputDir)
	if err := utils.WriteLinesToFile(rawURLsFile, urls); err != nil {
		return fmt.Errorf("failed to save raw URLs file: %w", err)
	}
	utils.LogInfo("Saved %d raw URLs to %s", len(urls), rawURLsFile)

	// ────────────────────────────────────────────
	// Stage 3.5: URL Deduplication (uro)
	// ────────────────────────────────────────────
	utils.LogInfo("▶ Stage 3.5: URL Deduplication (uro)")
	urlsFile := fmt.Sprintf("%s/urls.txt", domainOutputDir)
	filteredURLs, err := urlenum.DeduplicateWithUro(cfg, rawURLsFile, urlsFile)
	if err != nil {
		utils.LogWarn("uro failed: %v, using raw URLs", err)
		filteredURLs = urls
		if writeErr := utils.WriteLinesToFile(urlsFile, urls); writeErr != nil {
			return fmt.Errorf("failed to save URLs file: %w", writeErr)
		}
	}
	utils.LogInfo("uro reduced %d → %d URLs", len(urls), len(filteredURLs))

	// ────────────────────────────────────────────
	// Stage 4 & 5: Nuclei Scan + Discord Reporting (parallel)
	// ────────────────────────────────────────────
	utils.LogInfo("▶ Stage 4: Nuclei DAST Scan + Discord Reporting")

	// Create a channel to stream findings from scanner to reporter
	findings := make(chan scanner.Finding, 100)

	// Start Discord reporter in a goroutine (consumes findings in parallel)
	rep := reporter.New(cfg, domain)
	var reportWg sync.WaitGroup
	reportWg.Add(1)
	go func() {
		defer reportWg.Done()
		rep.StreamFindings(findings)
	}()

	// Run nuclei scanner (produces findings into the channel)
	if err := scanner.Scan(cfg, urlsFile, domainOutputDir, findings); err != nil {
		utils.LogError("Nuclei scan error for %s: %v", domain, err)
	}

	// Wait for reporter to finish processing all findings
	reportWg.Wait()

	utils.LogSuccess("Pipeline complete for %s", domain)
	return nil
}
