package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RetrivedMods/envguard/internal/config"
	"github.com/RetrivedMods/envguard/internal/detectors"
)

type Finding struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Confidence  int    `json:"confidence"`
	Match       string `json:"match"`
	Description string `json:"description"`
}

type Result struct {
	Version      string    `json:"version"`
	Path         string    `json:"path"`
	FilesScanned int       `json:"files_scanned"`
	LinesScanned int       `json:"lines_scanned"`
	DurationMS   int64     `json:"duration_ms"`
	Findings     []Finding `json:"findings"`
}

func (r Result) ShouldFail(level string) bool {
	threshold := severityValue(strings.ToUpper(level))

	if threshold == 0 {
		threshold = 3
	}

	for _, finding := range r.Findings {
		if severityValue(finding.Severity) >= threshold {
			return true
		}
	}

	return false
}

func Scan(root string, cfg config.Config, verbose bool) (Result, error) {
	start := time.Now()

	result := Result{
		Version: "0.1.0",
		Path:    root,
	}

	root, err := filepath.Abs(root)
	if err != nil {
		return result, err
	}

	patterns := loadIgnore(root, cfg.Scan.Exclude)
	maxSize := parseSize(cfg.Scan.MaxFileSize)

	var files []string

	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if info.IsDir() {
			if path != root && excluded(path, root, patterns) {
				return filepath.SkipDir
			}

			return nil
		}

		if excluded(path, root, patterns) ||
			!ShouldScanFile(path) ||
			isBinary(path) ||
			info.Size() > maxSize {
			return nil
		}

		files = append(files, path)
		return nil
	})

	if err != nil {
		return result, err
	}

	sort.Strings(files)

	for _, path := range files {
		if verbose {
			fmt.Println("Scanning", path)
		}

		scanFile(path, root, cfg, &result)
	}

	result.DurationMS = time.Since(start).Milliseconds()

	sortFindings(result.Findings)

	return result, nil
}

func scanFile(path, root string, cfg config.Config, result *Result) {
	file, err := os.Open(path)
	if err != nil {
		return
	}

	defer file.Close()

	result.FilesScanned++

	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		relativePath = path
	}

	relativePath = filepath.ToSlash(relativePath)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		result.LinesScanned++

		scanLine(
			scanner.Text(),
			lineNumber,
			relativePath,
			cfg,
			result,
		)
	}
}

func scanLine(
	line string,
	lineNumber int,
	file string,
	cfg config.Config,
	result *Result,
) {
	for _, rule := range detectors.Rules {
		matches := rule.Pattern.FindAllStringSubmatchIndex(line, -1)

		for _, match := range matches {
			start := match[0]
			value := line[match[0]:match[1]]

			if rule.ID == "generic-secret" && len(match) >= 4 {
				start = match[2]
				value = line[match[2]:match[3]]
			}

			if rule.Validate != nil && !rule.Validate(value) {
				continue
			}

			if detectors.IsPlaceholder(value) {
				continue
			}

			confidence := confidenceFor(rule.ID, value)

			result.Findings = append(result.Findings, Finding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Severity:    rule.Severity,
				File:        file,
				Line:        lineNumber,
				Column:      start + 1,
				Confidence:  confidence,
				Match:       redact(value),
				Description: rule.Description,
			})
		}
	}

	if cfg.Entropy.Enabled {
		scanEntropy(
			line,
			lineNumber,
			file,
			cfg,
			result,
		)
	}
}

func scanEntropy(
	line string,
	lineNumber int,
	file string,
	cfg config.Config,
	result *Result,
) {
	for _, token := range tokens(line) {
		if len(token) < cfg.Entropy.MinLength {
			continue
		}

		if detectors.IsPlaceholder(token) {
			continue
		}

		if likelyHash(token) {
			continue
		}

		if !secretShape(token) {
			continue
		}

		if detectors.ShannonEntropy(token) < cfg.Entropy.Threshold {
			continue
		}

		if alreadyDetected(result.Findings, file, lineNumber, token) {
			continue
		}

		confidence := 72

		if sensitiveContext(line, token) {
			confidence = 84
		}

		result.Findings = append(result.Findings, Finding{
			RuleID:      "high-entropy",
			RuleName:    "High Entropy String",
			Severity:    "MEDIUM",
			File:        file,
			Line:        lineNumber,
			Column:      strings.Index(line, token) + 1,
			Confidence:  confidence,
			Match:       redact(token),
			Description: "Unusually random string in a potentially sensitive context",
		})
	}
}

func ShouldScanFile(path string) bool {
	normalized := filepath.ToSlash(path)
	lower := strings.ToLower(normalized)
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	ignoredDirectories := []string{
		"/.git/",
		"/node_modules/",
		"/vendor/",
		"/.venv/",
		"/venv/",
		"/__pycache__/",
		"/.gradle/",
		"/build/",
		"/dist/",
		"/target/",
		"/coverage/",
		"/.idea/",
		"/.vscode/",
		"/.cache/",
		"/app/build/",
		"/app/.cxx/",
		"/.cxx/",
	}

	normalizedForMatch := "/" + strings.TrimPrefix(lower, "/") + "/"

	for _, directory := range ignoredDirectories {
		if strings.Contains(normalizedForMatch, directory) {
			return false
		}
	}

	ignoredFiles := map[string]struct{}{
		"package-lock.json": {},
		"yarn.lock":         {},
		"pnpm-lock.yaml":    {},
		"go.sum":            {},
		"cargo.lock":        {},
		"composer.lock":     {},
		"gemfile.lock":      {},
		"poetry.lock":       {},
		"pipfile.lock":      {},
	}

	if _, ok := ignoredFiles[base]; ok {
		return false
	}

	testSuffixes := []string{
		".test.go",
		"_test.go",
		".spec.js",
		".spec.ts",
		".test.js",
		".test.ts",
		".spec.jsx",
		".spec.tsx",
		".test.jsx",
		".test.tsx",
	}

	for _, suffix := range testSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}

	switch ext {
	case ".md", ".txt":
		return false
	}

	return true
}

func tokens(line string) []string {
	var result []string
	var builder strings.Builder

	flush := func() {
		if builder.Len() == 0 {
			return
		}

		result = append(result, builder.String())
		builder.Reset()
	}

	for _, char := range line {
		if isTokenCharacter(char) {
			builder.WriteRune(char)
		} else {
			flush()
		}
	}

	flush()

	return result
}

func isTokenCharacter(char rune) bool {
	return (char >= 'A' && char <= 'Z') ||
		(char >= 'a' && char <= 'z') ||
		(char >= '0' && char <= '9') ||
		char == '_' ||
		char == '-' ||
		char == '+' ||
		char == '/' ||
		char == '='
}

func secretShape(value string) bool {
	var upper bool
	var lower bool
	var digit bool
	var special bool

	for _, char := range value {
		switch {
		case char >= 'A' && char <= 'Z':
			upper = true
		case char >= 'a' && char <= 'z':
			lower = true
		case char >= '0' && char <= '9':
			digit = true
		default:
			special = true
		}
	}

	return upper && lower && digit && (special || len(value) >= 28)
}

func sensitiveContext(line, token string) bool {
	index := strings.Index(line, token)

	if index < 0 {
		return false
	}

	before := strings.ToLower(line[:index])

	contexts := []string{
		"api_key",
		"apikey",
		"api-key",
		"secret",
		"password",
		"passwd",
		"token",
		"access_key",
		"access-key",
		"private_key",
		"private-key",
		"client_secret",
		"credential",
		"auth",
	}

	for _, context := range contexts {
		if strings.Contains(before, context) {
			return true
		}
	}

	return false
}

func alreadyDetected(findings []Finding, file string, line int, token string) bool {
	for _, finding := range findings {
		if finding.File != file || finding.Line != line {
			continue
		}

		if finding.RuleID == "high-entropy" {
			continue
		}

		if strings.Contains(strings.Trim(finding.Match, "*"), token) {
			return true
		}
	}

	return false
}

func likelyHash(value string) bool {
	switch len(value) {
	case 32, 40, 64, 96, 128:
	default:
		return false
	}

	for _, char := range strings.ToLower(value) {
		if !((char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'f')) {
			return false
		}
	}

	return true
}

func redact(value string) string {
	if len(value) <= 8 {
		return "********"
	}

	prefix := 4

	if len(value) < 12 {
		prefix = 2
	}

	return value[:prefix] + strings.Repeat("*", len(value)-prefix)
}

func confidenceFor(ruleID, value string) int {
	switch ruleID {
	case "generic-secret":
		return 82
	case "high-entropy":
		return 72
	case "private-key":
		return 98
	default:
		if len(value) >= 40 {
			return 95
		}

		return 92
	}
}

func duplicate(findings []Finding, finding Finding) bool {
	for _, existing := range findings {
		if existing.File == finding.File &&
			existing.Line == finding.Line &&
			existing.RuleID == finding.RuleID &&
			existing.Column == finding.Column {
			return true
		}
	}

	return false
}

func severityValue(severity string) int {
	switch strings.ToUpper(severity) {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	default:
		return 0
	}
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		left := severityValue(findings[i].Severity)
		right := severityValue(findings[j].Severity)

		if left != right {
			return left > right
		}

		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}

		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}

		return findings[i].Column < findings[j].Column
	})
}

func parseSize(value string) int64 {
	value = strings.ToUpper(strings.TrimSpace(value))

	var number float64
	var unit string

	if _, err := fmt.Sscanf(value, "%f%s", &number, &unit); err != nil {
		return 5 * 1024 * 1024
	}

	switch unit {
	case "KB":
		return int64(number * 1024)
	case "MB":
		return int64(number * 1024 * 1024)
	case "GB":
		return int64(number * 1024 * 1024 * 1024)
	default:
		return int64(number)
	}
}

func loadIgnore(root string, defaults []string) []string {
	result := append([]string{}, defaults...)

	data, err := os.ReadFile(filepath.Join(root, ".envguardignore"))
	if err != nil {
		return result
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		result = append(result, line)
	}

	return result
}

func excluded(path, root string, patterns []string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}

	relative = filepath.ToSlash(relative)
	base := filepath.Base(relative)

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		pattern = filepath.ToSlash(pattern)
		pattern = strings.TrimSuffix(pattern, "/")

		if pattern == "" {
			continue
		}

		if ok, _ := filepath.Match(pattern, relative); ok {
			return true
		}

		if ok, _ := filepath.Match(pattern, base); ok {
			return true
		}

		if relative == pattern ||
			strings.HasPrefix(relative, pattern+"/") ||
			strings.Contains(relative, "/"+pattern+"/") {
			return true
		}
	}

	return false
}

func isBinary(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png",
		".jpg",
		".jpeg",
		".gif",
		".webp",
		".ico",
		".bmp",
		".tif",
		".tiff",
		".mp3",
		".wav",
		".ogg",
		".flac",
		".mp4",
		".mkv",
		".avi",
		".mov",
		".zip",
		".gz",
		".bz2",
		".xz",
		".7z",
		".rar",
		".tar",
		".iso",
		".exe",
		".dll",
		".so",
		".dylib",
		".bin",
		".class",
		".jar",
		".war",
		".pdf",
		".woff",
		".woff2",
		".ttf",
		".otf",
		".pyc",
		".o",
		".a":
		return true
	default:
		return false
	}
}

func InstallHook() error {
	root, err := exec.Command(
		"git",
		"rev-parse",
		"--show-toplevel",
	).Output()

	if err != nil {
		return fmt.Errorf("not inside a Git repository")
	}

	hookPath := filepath.Join(
		strings.TrimSpace(string(root)),
		".git",
		"hooks",
		"pre-commit",
	)

	content := "#!/bin/sh\n" +
		"envguard scan .\n" +
		"status=$?\n" +
		"[ $status -eq 0 ] || exit $status\n"

	return os.WriteFile(hookPath, []byte(content), 0755)
}

func ScanHistory() error {
	output, err := exec.Command(
		"git",
		"log",
		"--all",
		"--format=%H",
	).Output()

	if err != nil {
		return fmt.Errorf("not inside a Git repository")
	}

	commits := strings.Fields(string(output))

	fmt.Printf(
		"EnvGuard Git History Scanner\n\nScanning %d commits...\n",
		len(commits),
	)

	for _, commit := range commits {
		files, err := exec.Command(
			"git",
			"diff-tree",
			"--no-commit-id",
			"--name-only",
			"-r",
			commit,
		).Output()

		if err != nil {
			continue
		}

		for _, file := range strings.Fields(string(files)) {
			if !ShouldScanFile(file) {
				continue
			}

			data, err := exec.Command(
				"git",
				"show",
				commit+":"+file,
			).Output()

			if err != nil || len(data) > 5*1024*1024 {
				continue
			}

			for _, rule := range detectors.Rules {
				if rule.Pattern.Find(data) == nil {
					continue
				}

				shortCommit := commit

				if len(shortCommit) > 12 {
					shortCommit = shortCommit[:12]
				}

				fmt.Printf(
					"\n%s\nCommit: %s\nFile: %s\nDetector: %s\nSeverity: %s\n",
					rule.Name,
					shortCommit,
					file,
					rule.ID,
					rule.Severity,
				)

				break
			}
		}
	}

	return nil
}