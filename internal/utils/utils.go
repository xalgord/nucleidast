package utils

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
	ColorGray   = "\033[90m"
)

var (
	Verbose bool
	logMu   sync.Mutex
)

func timestamp() string {
	return time.Now().Format("15:04:05")
}

func LogInfo(format string, args ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[INF]%s %s\n", ColorGray, timestamp(), ColorReset, ColorCyan, ColorReset, msg)
}

func LogSuccess(format string, args ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[OK]%s  %s\n", ColorGray, timestamp(), ColorReset, ColorGreen, ColorReset, msg)
}

func LogWarn(format string, args ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[WRN]%s %s\n", ColorGray, timestamp(), ColorReset, ColorYellow, ColorReset, msg)
}

func LogError(format string, args ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s]%s %s[ERR]%s %s\n", ColorGray, timestamp(), ColorReset, ColorRed, ColorReset, msg)
}

func LogDebug(format string, args ...interface{}) {
	if !Verbose {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[%s] [DBG] %s%s\n", ColorGray, timestamp(), msg, ColorReset)
}

// ToolExists checks if a binary is available in PATH
func ToolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RunCommand executes a command and returns stdout lines
func RunCommand(ctx context.Context, name string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	LogDebug("Running: %s %s", name, strings.Join(args, " "))

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("command timed out: %s", name)
		}
		// cmd.Output() returns stdout even on non-zero exit
		if len(output) > 0 {
			return parseLines(string(output)), nil
		}
		// Include stderr in error message for debugging
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("command failed: %s: %v (stderr: %s)", name, err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("command failed: %s: %v", name, err)
	}

	return parseLines(string(output)), nil
}

// RunShellCommand runs a command through bash
func RunShellCommand(ctx context.Context, shellCmd string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "bash", "-c", shellCmd)
	LogDebug("Running shell: %s", shellCmd)

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("shell command timed out")
		}
		if len(output) > 0 {
			return parseLines(string(output)), nil
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("shell command failed: %v (stderr: %s)", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("shell command failed: %v", err)
	}

	return parseLines(string(output)), nil
}

func parseLines(s string) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// DeduplicateLines removes duplicate strings preserving order
func DeduplicateLines(lines []string) []string {
	seen := make(map[string]struct{}, len(lines))
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if lower == "" {
			continue
		}
		if _, exists := seen[lower]; !exists {
			seen[lower] = struct{}{}
			result = append(result, strings.TrimSpace(line))
		}
	}
	return result
}

// WriteLinesToFile writes a slice of strings to a file (one per line)
func WriteLinesToFile(filepath string, lines []string) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

// ReadLinesFromFile reads a file and returns non-empty lines
func ReadLinesFromFile(filepath string) ([]string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	// Increase buffer size for large files
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// ExpandHome expands ~ to the user's home directory
func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return strings.Replace(path, "~", home, 1)
	}
	return path
}

// EnsureDir creates a directory if it doesn't exist
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// Banner prints the program banner
func Banner() {
	banner := `
    ╔═══════════════════════════════════════════════╗
    ║           %sNucleiDAST%s v1.1.3                   ║
    ║     Automated DAST Scanning Pipeline          ║
    ║                                               ║
    ║  Subdomains → DNS → URLs → Nuclei → Discord   ║
    ╚═══════════════════════════════════════════════╝
`
	fmt.Printf(banner, ColorBold+ColorCyan, ColorReset)
}
