package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/xalgord/nucleidast/internal/config"
	"github.com/xalgord/nucleidast/internal/runner"
	"github.com/xalgord/nucleidast/internal/utils"

	"github.com/spf13/cobra"
)

var (
	target     string
	listFile   string
	configFile string
	outputDir  string
	verbose    bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "nucleidast",
		Short:   "NucleiDAST — Automated DAST Scanning Pipeline",
		Version: utils.Version,
		Long: `NucleiDAST orchestrates an end-to-end DAST scanning pipeline:
  Subdomain Enumeration → DNS Resolution → URL Enumeration → Nuclei DAST → Discord Reporting

All stages run in parallel where possible for maximum efficiency.
Run as root to ensure all tools are accessible.`,
		RunE: execute,
	}

	rootCmd.Flags().StringVarP(&target, "target", "t", "", "Single target domain (e.g., example.com)")
	rootCmd.Flags().StringVarP(&listFile, "list", "l", "", "File containing list of target domains (one per line)")
	defaultConfig := filepath.Join(os.Getenv("HOME"), ".config", "nucleidast", "config.yaml")
	rootCmd.Flags().StringVarP(&configFile, "config", "c", defaultConfig, "Path to config file")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory (overrides config)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func execute(cmd *cobra.Command, args []string) error {
	// Validate input
	if target == "" && listFile == "" {
		return fmt.Errorf("provide at least one target with -t or a list file with -l")
	}

	// Load config
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	// Apply CLI overrides
	if verbose {
		cfg.Verbose = true
	}
	if outputDir != "" {
		cfg.OutputDir = outputDir
	}
	utils.Verbose = cfg.Verbose

	// Ensure output directory exists
	if err := utils.EnsureDir(cfg.OutputDir); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Collect targets
	var targets []string

	if target != "" {
		targets = append(targets, target)
	}

	if listFile != "" {
		lines, err := utils.ReadLinesFromFile(listFile)
		if err != nil {
			return fmt.Errorf("failed to read target list: %w", err)
		}
		targets = append(targets, lines...)
	}

	targets = utils.DeduplicateLines(targets)

	if len(targets) == 0 {
		return fmt.Errorf("no targets provided")
	}

	// Run the pipeline
	return runner.Run(cfg, targets)
}
