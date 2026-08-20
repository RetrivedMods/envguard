package reporter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/RetrivedMods/envguard/internal/scanner"
)

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type sarifLocation struct {
	URI    string      `json:"uri"`
	Region sarifRegion `json:"region"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

func Terminal(r scanner.Result) {
	printHeader(r)

	if len(r.Findings) == 0 {
		fmt.Println("✓ No potential secrets found")
		return
	}

	fmt.Println("Findings:")
	fmt.Println()

	for _, finding := range r.Findings {
		printFinding(finding)
	}

	fmt.Println("────────────────────────────────────────")
	fmt.Printf("\n%d potential secrets found\n", len(r.Findings))
}

func printHeader(r scanner.Result) {
	fmt.Printf("EnvGuard v%s\n\n", r.Version)
	fmt.Printf("Scanning %s\n\n", r.Path)
	fmt.Printf("✓ %d files scanned\n", r.FilesScanned)
	fmt.Printf("✓ %d lines scanned\n", r.LinesScanned)
	fmt.Printf("✓ %dms\n\n", r.DurationMS)
}

func printFinding(f scanner.Finding) {
	fmt.Printf(
		"%-7s %s:%d:%d\n",
		f.Severity,
		f.File,
		f.Line,
		f.Column,
	)
	fmt.Printf("        %s\n", f.RuleName)
	fmt.Printf("        Confidence: %d%%\n", f.Confidence)
	fmt.Printf("        %s\n\n", f.Match)
}

func SARIF(r scanner.Result) ([]byte, error) {
	report := newSARIFReport(r)

	for _, finding := range r.Findings {
		report.Runs[0].Results = append(
			report.Runs[0].Results,
			toSARIFResult(finding),
		)
	}

	return json.MarshalIndent(report, "", "  ")
}

func newSARIFReport(r scanner.Result) sarifReport {
	return sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "EnvGuard",
						Version: r.Version,
					},
				},
				Results: make([]sarifResult, 0, len(r.Findings)),
			},
		},
	}
}

func toSARIFResult(f scanner.Finding) sarifResult {
	return sarifResult{
		RuleID: f.RuleID,
		Level:  strings.ToLower(f.Severity),
		Message: sarifMessage{
			Text: f.Description,
		},
		Locations: []sarifLocation{
			{
				URI: f.File,
				Region: sarifRegion{
					StartLine:   f.Line,
					StartColumn: f.Column,
				},
			},
		},
	}
}