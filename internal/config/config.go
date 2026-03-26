package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/xalgord/nucleidast/internal/utils"

	"gopkg.in/yaml.v3"
)

type DiscordConfig struct {
	WebhookURL string   `yaml:"webhook_url"`
	NotifyOn   []string `yaml:"notify_on"`
	BatchSize  int      `yaml:"batch_size"`
}

type SubdomainConfig struct {
	Threads        int  `yaml:"threads"`
	UseSubfinder   bool `yaml:"use_subfinder"`
	UseFindomain   bool `yaml:"use_findomain"`
	UseAssetfinder bool `yaml:"use_assetfinder"`
}

type DNSConfig struct {
	Threads int `yaml:"threads"`
}

type URLEnumConfig struct {
	UseWaymore     bool   `yaml:"use_waymore"`
	UseGau         bool   `yaml:"use_gau"`
	UseParamspider bool   `yaml:"use_paramspider"`
	UseGospider    bool   `yaml:"use_gospider"`
	PythonVenv     string `yaml:"python_venv"`
}

// NucleiScanProfile defines a single nuclei scan configuration
type NucleiScanProfile struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	RateLimit   int      `yaml:"rate_limit"`
	Concurrency int      `yaml:"concurrency"`
	DAST        bool     `yaml:"dast"`
	Dashboard   bool     `yaml:"dashboard"`
	Tags        string   `yaml:"tags"`
	Templates   []string `yaml:"templates"`
	ExtraArgs   []string `yaml:"extra_args"`
	Enabled     bool     `yaml:"enabled"`
}

type NucleiConfig struct {
	Scans []NucleiScanProfile `yaml:"scans"`
}

type Config struct {
	Discord              DiscordConfig   `yaml:"discord"`
	Subdomain            SubdomainConfig `yaml:"subdomain"`
	DNS                  DNSConfig       `yaml:"dns"`
	URLEnum              URLEnumConfig   `yaml:"urlenum"`
	Nuclei               NucleiConfig    `yaml:"nuclei"`
	OutputDir            string          `yaml:"output_dir"`
	MaxConcurrentTargets int             `yaml:"max_concurrent_targets"`
	Verbose              bool            `yaml:"verbose"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Discord: DiscordConfig{
			NotifyOn:  []string{"critical", "high", "medium"},
			BatchSize: 10,
		},
		Subdomain: SubdomainConfig{
			Threads:        100,
			UseSubfinder:   true,
			UseFindomain:   true,
			UseAssetfinder: true,
		},
		DNS: DNSConfig{
			Threads: 100,
		},
		URLEnum: URLEnumConfig{
			UseWaymore:     true,
			UseGau:         true,
			UseParamspider: true,
			UseGospider:    true,
			PythonVenv:     "~/venv/bin/activate",
		},
		Nuclei: NucleiConfig{
			Scans: []NucleiScanProfile{
				{
					Name:        "SQL Injection DAST",
					Severity:    "critical,high,medium",
					RateLimit:   5,
					Concurrency: 5,
					DAST:        true,
					Dashboard:   true,
					Enabled:     true,
				},
				{
					Name:        "SMTP Credentials",
					Severity:    "critical,high,medium,low,info",
					RateLimit:   10,
					Concurrency: 10,
					DAST:        false,
					Dashboard:   true,
					Tags:        "smtp",
					Enabled:     true,
				},
			},
		},
		OutputDir:            "./output",
		MaxConcurrentTargets: 3,
		Verbose:              false,
	}
}

// Load reads and parses the config file
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			utils.LogWarn("Config file not found at %s, using defaults", path)
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Expand paths
	cfg.OutputDir = utils.ExpandHome(cfg.OutputDir)
	cfg.URLEnum.PythonVenv = utils.ExpandHome(cfg.URLEnum.PythonVenv)

	// Validate
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.MaxConcurrentTargets < 1 {
		c.MaxConcurrentTargets = 1
	}
	// Validate each scan profile
	for i := range c.Nuclei.Scans {
		scan := &c.Nuclei.Scans[i]
		if scan.RateLimit < 1 {
			scan.RateLimit = 5
		}
		if scan.Concurrency < 1 {
			scan.Concurrency = 5
		}
		if scan.Name == "" {
			scan.Name = fmt.Sprintf("Scan %d", i+1)
		}
	}
	if c.Discord.BatchSize < 1 {
		c.Discord.BatchSize = 10
	}
	if c.Discord.WebhookURL != "" && !strings.HasPrefix(c.Discord.WebhookURL, "https://discord.com/api/webhooks/") {
		return fmt.Errorf("invalid discord webhook URL: must start with https://discord.com/api/webhooks/")
	}
	return nil
}

// ShouldNotify checks if a severity level should trigger a Discord notification
func (c *Config) ShouldNotify(severity string) bool {
	severity = strings.ToLower(severity)
	for _, s := range c.Discord.NotifyOn {
		if strings.ToLower(s) == severity {
			return true
		}
	}
	return false
}

// EnabledScans returns only the enabled scan profiles
func (c *Config) EnabledScans() []NucleiScanProfile {
	var enabled []NucleiScanProfile
	for _, scan := range c.Nuclei.Scans {
		if scan.Enabled {
			enabled = append(enabled, scan)
		}
	}
	return enabled
}
