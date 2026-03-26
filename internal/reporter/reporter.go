package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/nucleidast/internal/config"
	"github.com/xalgord/nucleidast/internal/scanner"
	"github.com/xalgord/nucleidast/internal/utils"
)

// Discord embed color codes
const (
	ColorCritical = 0xFF0000 // Red
	ColorHigh     = 0xFF6600 // Orange
	ColorMedium   = 0xFFCC00 // Yellow
	ColorLow      = 0x00CCFF // Cyan
	ColorInfo     = 0x808080 // Gray
	ColorSuccess  = 0x00FF00 // Green
)

// Discord webhook payload structures
type WebhookPayload struct {
	Username  string  `json:"username,omitempty"`
	AvatarURL string  `json:"avatar_url,omitempty"`
	Content   string  `json:"content,omitempty"`
	Embeds    []Embed `json:"embeds,omitempty"`
}

type Embed struct {
	Title       string  `json:"title,omitempty"`
	Description string  `json:"description,omitempty"`
	Color       int     `json:"color,omitempty"`
	Fields      []Field `json:"fields,omitempty"`
	Footer      *Footer `json:"footer,omitempty"`
	Timestamp   string  `json:"timestamp,omitempty"`
}

type Field struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type Footer struct {
	Text string `json:"text"`
}

// Reporter handles streaming findings to Discord
type Reporter struct {
	cfg       *config.Config
	client    *http.Client
	mu        sync.Mutex
	counts    map[string]int
	domain    string
}

// New creates a new Reporter instance
func New(cfg *config.Config, domain string) *Reporter {
	return &Reporter{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		counts: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
		},
		domain: domain,
	}
}

// StreamFindings reads findings from channel and reports them to Discord in parallel
func (r *Reporter) StreamFindings(findings <-chan scanner.Finding) {
	if r.cfg.Discord.WebhookURL == "" {
		utils.LogWarn("Discord webhook URL not configured, skipping reporting")
		// Still drain the channel to avoid blocking
		for range findings {
		}
		return
	}

	// Send scan started notification
	r.sendScanStarted()

	for finding := range findings {
		severity := strings.ToLower(finding.Severity)

		// Track counts
		r.mu.Lock()
		r.counts[severity]++
		r.mu.Unlock()

		// Check if we should notify for this severity
		if !r.cfg.ShouldNotify(severity) {
			continue
		}

		// Send to Discord
		if err := r.sendFinding(finding); err != nil {
			utils.LogWarn("Failed to send finding to Discord: %v", err)
		}

		// Respect Discord rate limits (5 requests per 2 seconds)
		time.Sleep(500 * time.Millisecond)
	}

	// Send summary
	r.sendSummary()
}

func (r *Reporter) sendScanStarted() {
	payload := WebhookPayload{
		Username: "NucleiDAST",
		Embeds: []Embed{
			{
				Title:       "🔍 Scan Started",
				Description: fmt.Sprintf("DAST scan initiated for **%s**", r.domain),
				Color:       0x5865F2, // Discord blurple
				Footer:      &Footer{Text: "NucleiDAST Pipeline"},
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	if err := r.send(payload); err != nil {
		utils.LogWarn("Failed to send scan started notification: %v", err)
	}
}

func (r *Reporter) sendFinding(f scanner.Finding) error {
	severity := strings.ToLower(f.Severity)
	color := severityToColor(severity)

	// Build description
	desc := ""
	if f.Description != "" {
		desc = truncate(f.Description, 300)
	}

	fields := []Field{
		{Name: "🎯 Target", Value: fmt.Sprintf("`%s`", truncate(f.MatchedAt, 200)), Inline: false},
		{Name: "📋 Template", Value: fmt.Sprintf("`%s`", f.Template), Inline: true},
		{Name: "⚡ Severity", Value: fmt.Sprintf("**%s**", strings.ToUpper(severity)), Inline: true},
	}

	if f.Host != "" {
		fields = append(fields, Field{Name: "🌐 Host", Value: fmt.Sprintf("`%s`", f.Host), Inline: true})
	}

	if f.MatcherName != "" {
		fields = append(fields, Field{Name: "🔗 Matcher", Value: fmt.Sprintf("`%s`", f.MatcherName), Inline: true})
	}

	if len(f.ExtractedResults) > 0 {
		extracted := strings.Join(f.ExtractedResults, "\n")
		fields = append(fields, Field{
			Name:  "📤 Extracted",
			Value: fmt.Sprintf("```\n%s\n```", truncate(extracted, 500)),
		})
	}

	if f.CURLCommand != "" {
		fields = append(fields, Field{
			Name:  "🖥️ cURL",
			Value: fmt.Sprintf("```\n%s\n```", truncate(f.CURLCommand, 500)),
		})
	}

	name := f.Name
	if name == "" {
		name = f.Template
	}

	embed := Embed{
		Title:       fmt.Sprintf("%s %s", severityEmoji(severity), name),
		Description: desc,
		Color:       color,
		Fields:      fields,
		Footer:      &Footer{Text: fmt.Sprintf("NucleiDAST • %s", r.domain)},
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	payload := WebhookPayload{
		Username: "NucleiDAST",
		Embeds:   []Embed{embed},
	}

	return r.send(payload)
}

func (r *Reporter) sendSummary() {
	r.mu.Lock()
	counts := make(map[string]int)
	total := 0
	for k, v := range r.counts {
		counts[k] = v
		total += v
	}
	r.mu.Unlock()

	desc := fmt.Sprintf("Scan completed for **%s**\n\n", r.domain)
	desc += fmt.Sprintf("🔴 **Critical**: %d\n", counts["critical"])
	desc += fmt.Sprintf("🟠 **High**: %d\n", counts["high"])
	desc += fmt.Sprintf("🟡 **Medium**: %d\n", counts["medium"])
	desc += fmt.Sprintf("🔵 **Low**: %d\n", counts["low"])
	desc += fmt.Sprintf("⚪ **Info**: %d\n", counts["info"])
	desc += fmt.Sprintf("\n**Total: %d findings**", total)

	color := ColorSuccess
	if counts["critical"] > 0 {
		color = ColorCritical
	} else if counts["high"] > 0 {
		color = ColorHigh
	} else if counts["medium"] > 0 {
		color = ColorMedium
	}

	payload := WebhookPayload{
		Username: "NucleiDAST",
		Embeds: []Embed{
			{
				Title:       "📊 Scan Summary",
				Description: desc,
				Color:       color,
				Footer:      &Footer{Text: "NucleiDAST Pipeline"},
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	if err := r.send(payload); err != nil {
		utils.LogError("Failed to send summary to Discord: %v", err)
	} else {
		utils.LogSuccess("Scan summary sent to Discord")
	}
}

func (r *Reporter) send(payload WebhookPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := r.client.Post(r.cfg.Discord.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == 429 {
		utils.LogWarn("Discord rate limited, waiting 5 seconds...")
		time.Sleep(5 * time.Second)
		// Retry once
		resp2, err := r.client.Post(r.cfg.Discord.WebhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			return err
		}
		defer resp2.Body.Close()
		if resp2.StatusCode >= 400 {
			return fmt.Errorf("discord webhook returned status %d after retry", resp2.StatusCode)
		}
		return nil
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func severityToColor(severity string) int {
	switch severity {
	case "critical":
		return ColorCritical
	case "high":
		return ColorHigh
	case "medium":
		return ColorMedium
	case "low":
		return ColorLow
	case "info":
		return ColorInfo
	default:
		return ColorInfo
	}
}

func severityEmoji(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	case "info":
		return "⚪"
	default:
		return "⚪"
	}
}

func truncate(s string, maxLen int) string {
	if maxLen <= 3 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-3]) + "..."
}
