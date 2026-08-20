# envGuard

**Catch env secrets before they reach Git.**

![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)

envGuard checks your code for accidentally exposed API keys, tokens, passwords, and other secrets before they reach Git.

Download `envguard.exe` from the [latest release](https://github.com/RetrivedMods/envguard/releases/latest).

## Usage

Initialize envGuard in your repo:

```bash
.\envguard.exe init
```

Scan the current directory:

```bash
.\envguard.exe scan .
```

Scan and output JSON:

```bash
.\envguard.exe scan . --json
```

Scan and output SARIF (for CI / code scanning integrations):

```bash
.\envguard.exe scan . --sarif
```

Install a Git pre-commit hook to block secrets before they're committed:

```bash
.\envguard.exe install-hook
```

Scan your entire Git history for previously committed secrets:

```bash
.\envguard.exe history
```

## Build from Source

```bash
go mod tidy
go test ./...
go vet ./...
go build -o envguard.exe ./cmd/envguard
```

## License

[MIT](LICENSE)