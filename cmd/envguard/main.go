package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RetrivedMods/envguard/internal/config"
	"github.com/RetrivedMods/envguard/internal/reporter"
	"github.com/RetrivedMods/envguard/internal/scanner"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "help", "--help", "-h":
		usage()
	case "init":
		if err := config.WriteDefault(".envguard.yaml"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println("Created .envguard.yaml")
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	case "install-hook":
		if err := scanner.InstallHook(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println("Installed Git pre-commit hook.")
	case "history":
		if err := scanner.ScanHistory(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("envGuard - Catch env secrets before they reach Git.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  envguard scan <path> [flags]")
	fmt.Println("  envguard init")
	fmt.Println("  envguard install-hook")
	fmt.Println("  envguard history")
	fmt.Println("  envguard version")
	fmt.Println()
	fmt.Println("Scan flags:")
	fmt.Println("  --json")
	fmt.Println("  --sarif")
	fmt.Println("  --quiet")
	fmt.Println("  --verbose")
	fmt.Println("  --severity <low|medium|high>")
	fmt.Println("  --no-ignore")
}

func runScan(args []string) error {
	path := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	jsonOut := fs.Bool("json", false, "")
	sarifOut := fs.Bool("sarif", false, "")
	quiet := fs.Bool("quiet", false, "")
	verbose := fs.Bool("verbose", false, "")
	noIgnore := fs.Bool("no-ignore", false, "")
	severity := fs.String("severity", "", "")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(".envguard.yaml")
	if err != nil {
		return err
	}
	if *noIgnore {
		cfg.Scan.Exclude = nil
	}
	if *severity != "" {
		cfg.Severity.FailOn = strings.ToUpper(*severity)
	}

	result, err := scanner.Scan(path, cfg, *verbose)
	if err != nil {
		return err
	}

	switch {
	case *jsonOut:
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case *sarifOut:
		data, err := reporter.SARIF(result)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case !*quiet:
		reporter.Terminal(result)
	}

	if result.ShouldFail(cfg.Severity.FailOn) {
		os.Exit(1)
	}
	return nil
}
