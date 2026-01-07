# Git Secrets Scanner (gss)

*Read this in other languages: [Русский](README_RU.md)*

A powerful command-line utility for scanning Git repositories to detect and identify potential security leaks such as API keys, passwords, tokens, database credentials, and other sensitive information.

## Features

- **Comprehensive Secret Detection**: Uses configurable rules and regex patterns to identify various types of secrets
- **Flexible Scanning Modes**: Scan entire history, last N commits, or specific branches
- **Configurable Rules**: YAML-based configuration for custom detection rules
- **False Positive Filtering**: Built-in filters to reduce false positives
- **Multiple Output Formats**: Generate human-readable text or machine-readable JSON reports
- **Clean Architecture**: Modular, testable, and maintainable codebase
- **Full Test Coverage**: Unit and integration tests included

## Installation

### Prerequisites

- Go 1.21 or later
- `golangci-lint` (optional, for linting)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/example/git-secrets-scanner.git
cd git-secrets-scanner

# Build the binary (Linux/MacOS)
go build -o bin/gss ./cmd/gss

# Build the binary (Windows)
go build -o bin/gss.exe ./cmd/gss

# The binary will be at ./bin/gss.exe (Windows) or ./bin/gss (Linux/macOS)
```

## Usage

### Basic Scanning

Scan the last 10 commits of the current repository:

```bash
./bin/gss scan . --last 10 --output text
```

### Scan Entire History

```bash
./bin/gss scan /path/to/repo --all-history --output text
```

### Scan Specific Branch

```bash
./bin/gss scan /path/to/repo --branch develop --output json
```

### Use Custom Configuration with Absolute Path

```bash
./bin/gss scan . --config /custom_rules/rules.yml --output text
```

### Use Custom Configuration with Relative Path

```bash
./bin/gss scan . --config ./rules/custom-rules.yml --output text
```

### Command-line Options

```
Usage:
  gss scan <repo-path> [flags]

Flags:
  -c, --config string      Path to the rules configuration file (default "config/rules.yml")
                           Supports both absolute and relative paths:
                           - Absolute: C:\rules\custom.yml or /etc/gss/rules.yml
                           - Relative: ./config/rules.yml or ../rules.yml
  -o, --output string      Output format: text or json (default "text")
      --all-history        Scan entire Git history
      --last int           Number of last commits to scan (default 10)
      --branch string      Branch name to scan (default: current branch)
  -v, --verbose            Enable verbose logging
  -h, --help              Show help information
```

## Configuration

### Rules File (config/rules.yml)

The detection rules are defined in YAML format:

```yaml
rules:
  - name: "Access Key"
    pattern: 'AKIA[0-9A-Z]{16}'
    keywords:
      - "access_key"
    priority: "critical"
    min_length: 20

  - name: "Generic API Key"
    pattern: '(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?'
    keywords:
      - "api_key"
      - "token"
    priority: "high"
    min_length: 32

false_positives:
  keywords:
    - "YOUR_API_KEY_HERE"
    - "example_token"
  patterns:
    - '(demo|example|sample|test)'
```

### Rule Fields

- **name**: Human-readable name of the rule
- **pattern**: Regular expression pattern to match secrets
- **keywords**: List of keywords to boost detection confidence
- **priority**: Severity level (low, medium, high, critical)
- **min_length**: Minimum length of matched secret

### False Positives

Configure false positive filters to reduce noise:

- **keywords**: Keywords that indicate a false positive
- **patterns**: Regex patterns that should be filtered out

## Output

### Text Report Format

```
=============================================================================
                    Git Secrets Scanner - Security Report
=============================================================================

SCAN SUMMARY
---
Commits scanned:        15
Files scanned:          42
Files with findings:    3
Total findings:         5
Scan duration:          2.345s

FINDINGS BY TYPE
---
  AWS Access Key                           : 2
  Database URL                             : 3

DETAILED FINDINGS

[1] Access Key
    File:       config/settings.py:45
    Commit:     a1b2c3d4 (John Doe)
    Message:    Add configuration
    Severity:   critical
    Confidence: 95%
    Value:      AK**...***
    Line:       access_key = "AKIAIOSFODNN7EXAMPLE"
```

### JSON Report Format

```json
{
  "statistics": {
    "commits_scanned": 15,
    "files_scanned": 42,
    "files_with_findings": 3,
    "findings_count": 5,
    "findings_by_type": {
      "AWS Access Key": 2,
      "Database URL": 3
    },
    "scan_duration": "2.345s"
  },
  "findings": [
    {
      "type": "AWS Access Key",
      "file_path": "config/settings.py",
      "line_number": 45,
      "commit_hash": "a1b2c3d4...",
      "severity": "critical",
      "confidence": 95,
      "masked_value": "AK**...***"
    }
  ],
  "errors": []
}
```

## Development

### Running Tests

```bash
# All tests with coverage
go test -v -race -cover ./...

# Unit tests only
go test -v -race ./internal/...

# Integration tests only
go test -v -race ./test/integration/...
```

### Code Formatting

```bash
# Format code
go fmt ./...

# Run linter (if installed)
golangci-lint run ./...
```

### Building

```bash
# Build the binary
go build -o bin/gss ./cmd/gss

# Clean build artifacts
go clean
```

## Security Considerations

- Secrets are masked in output reports (only first and last 2 characters shown)
- No secrets are logged to stdout (only in reports)
- Configurable false positive filters to avoid unnecessary alerts
- Support for custom ignore patterns similar to `.gitignore`

## Exit Codes

- `0`: Success, no secrets detected
- `1`: Error during execution or secrets detected
