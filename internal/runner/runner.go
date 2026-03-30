package runner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/nucleidast/internal/config"
	"github.com/xalgord/nucleidast/internal/dns"
	"github.com/xalgord/nucleidast/internal/reporter"
	"github.com/xalgord/nucleidast/internal/scanner"
	"github.com/xalgord/nucleidast/internal/subdomain"
	"github.com/xalgord/nucleidast/internal/urlenum"
	"github.com/xalgord/nucleidast/internal/utils"
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
	errs := make([]error, 0)
	var errorsMu sync.Mutex

	for _, target := range targets {
		// Validate domain before processing
		if !utils.IsValidDomain(target) {
			utils.LogError("Invalid domain name: %s — skipping", target)
			errorsMu.Lock()
			errs = append(errs, fmt.Errorf("%s: invalid domain name", target))
			errorsMu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // acquire semaphore

		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore

			if err := processDomain(cfg, domain); err != nil {
				utils.LogError("Pipeline failed for %s: %v", domain, err)
				errorsMu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", domain, err))
				errorsMu.Unlock()
			}
		}(target)
	}

	wg.Wait()

	elapsed := time.Since(start).Round(time.Second)
	utils.LogSuccess("All targets processed in %s", elapsed)

	if len(errs) > 0 {
		utils.LogWarn("%d target(s) had errors:", len(errs))
		var errMsgs []string
		for _, err := range errs {
			utils.LogError("  → %v", err)
			errMsgs = append(errMsgs, err.Error())
		}
		return fmt.Errorf("%s", strings.Join(errMsgs, "; "))
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

	// Save live subdomains
	liveSubsFile := fmt.Sprintf("%s/live_subdomains.txt", domainOutputDir)
	if err := utils.WriteLinesToFile(liveSubsFile, liveSubdomains); err != nil {
		utils.LogWarn("Failed to save live subdomains file: %v", err)
	}
	utils.LogInfo("Saved %d live subdomains to %s", len(liveSubdomains), liveSubsFile)

	// ────────────────────────────────────────────
	// Stage 3: URL Enumeration
	// ────────────────────────────────────────────
	utils.LogInfo("▶ Stage 3: URL Enumeration")
	urls := urlenum.Enumerate(cfg, domain, domainOutputDir)

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
	// Stage 4 & 5: Nuclei Scans + Discord Reporting (parallel)
	// ────────────────────────────────────────────
	enabledScans := cfg.EnabledScans()
	if len(enabledScans) == 0 {
		utils.LogWarn("No nuclei scan profiles enabled, skipping")
		return nil
	}

	utils.LogInfo("▶ Stage 4: Launching %d nuclei scan(s) in parallel", len(enabledScans))
	for _, s := range enabledScans {
		utils.LogInfo("  • %s (severity=%s, dast=%v, tags=%s)", s.Name, s.Severity, s.DAST, s.Tags)
	}

	// Single findings channel — all scan profiles write to it
	findings := make(chan scanner.Finding, 100)

	// Start Discord reporter (consumes findings)
	rep := reporter.New(cfg, domain)
	var reportWg sync.WaitGroup
	reportWg.Add(1)
	go func() {
		defer reportWg.Done()
		rep.StreamFindings(findings)
	}()

	// Launch all scan profiles in parallel
	var scanWg sync.WaitGroup
	for _, profile := range enabledScans {
		scanWg.Add(1)
		go func(p config.NucleiScanProfile) {
			defer scanWg.Done()
			if err := scanner.Scan(p, urlsFile, domainOutputDir, findings); err != nil {
				utils.LogError("[%s] scan error for %s: %v", p.Name, domain, err)
			}
		}(profile)
	}

	// Wait for all scans to finish, then close the channel
	scanWg.Wait()
	close(findings)

	// Wait for reporter to finish processing all findings
	reportWg.Wait()

	utils.LogSuccess("Pipeline complete for %s", domain)
	return nil
}
