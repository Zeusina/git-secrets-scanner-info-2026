// Package main provides the entry point for the git-secrets-scanner CLI application.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/analyzer"
	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/config"
	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/git"
	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/logger"
	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/report"
	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/validator"
	"github.com/spf13/cobra"
)

var (
	configPath   string
	outputFormat string
	allHistory   bool
	lastN        int
	branch       string
	verbose      bool
)

var rootCmd = &cobra.Command{
	Use:     "gss",
	Short:   "Git Secrets Scanner - Find secrets in Git repositories",
	Long:    "A command-line utility to scan Git repositories for accidental secret leaks",
	Version: "1.0.0",
}

var scanCmd = &cobra.Command{
	Use:   "scan <repo-path>",
	Short: "Scan a Git repository for secrets",
	Long:  "Scan a Git repository for potential secret leaks including API keys, passwords, and tokens",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	// Silence usage and errors to avoid duplicate output
	scanCmd.SilenceUsage = true
	scanCmd.SilenceErrors = true

	// Root command flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")

	// Scan command flags
	scanCmd.Flags().StringVarP(&configPath, "config", "c", "config/rules.yml", "Path to the rules configuration file")
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "Output format: text or json")
	scanCmd.Flags().BoolVar(&allHistory, "all-history", false, "Scan entire Git history")
	scanCmd.Flags().IntVar(&lastN, "last", 10, "Number of last commits to scan (if --all-history is not set)")
	scanCmd.Flags().StringVar(&branch, "branch", "", "Branch name to scan (default: current branch)")

	rootCmd.AddCommand(scanCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Set logging level
	logger.SetLevel(slog.LevelError)
	if verbose {
		logger.SetLevel(slog.LevelDebug)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	repoPath := args[0]

	// Validate output format
	if outputFormat != "text" && outputFormat != "json" {
		return fmt.Errorf("invalid output format: %s (must be 'text' or 'json')", outputFormat)
	}

	// Load configuration
	logger.Info(ctx, "Loading configuration", "file", configPath)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.Error(ctx, "Failed to load configuration", "error", err)
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create detector
	detector, err := analyzer.NewSecretDetector(cfg)
	if err != nil {
		logger.Error(ctx, "Failed to create detector", "error", err)
		return fmt.Errorf("failed to create detector: %w", err)
	}

	// Open repository
	logger.Info(ctx, "Opening repository", "path", repoPath)
	gitRepo, err := git.NewGitRepository(repoPath)
	if err != nil {
		logger.Error(ctx, "Failed to open repository", "error", err)
		return fmt.Errorf("failed to open repository: %w", err)
	}

	if err := gitRepo.Validate(ctx); err != nil {
		logger.Error(ctx, "Repository validation failed", "error", err)
		return fmt.Errorf("repository validation failed: %w", err)
	}

	// Initialize scan result
	result := &analyzer.ScanResult{
		Statistics: analyzer.Statistics{
			StartTime:          time.Now(),
			FindingsByType:     make(map[string]int),
			FindingsBySeverity: make(map[analyzer.Severity]int),
		},
	}

	// Get commits
	logger.Info(ctx, "Retrieving commits", "all_history", allHistory, "last_n", lastN)
	commitOpts := git.CommitOptions{
		AllHistory: allHistory,
		LastN:      lastN,
		Branch:     branch,
	}

	commits, err := gitRepo.GetCommits(ctx, commitOpts)
	if err != nil {
		logger.Error(ctx, "Failed to get commits", "error", err)
		result.AddError(err)
		return generateAndPrintReport(ctx, result, outputFormat)
	}

	result.Statistics.CommitsScanned = len(commits)
	logger.Info(ctx, "Starting scan", "commits_count", len(commits))

	filesWithFindings := make(map[string]bool)

	// Scan each commit
commitLoop:
	for _, commit := range commits {
		select {
		case <-ctx.Done():
			result.AddError(ctx.Err())
			break commitLoop
		default:
		}

		affectedFiles, err := gitRepo.GetAffectedFiles(ctx, commit.Hash)
		if err != nil {
			commitHash := commit.Hash

			if len(commit.Hash) > 8 { // Explicit check for commit hash len
				commitHash = commitHash[:8]
			}

			logger.Warn(ctx, "Failed to get affected files", "commit", commitHash, "error", err)
			result.AddError(err)
			continue
		}

		// Scan each file
		for _, filePath := range affectedFiles {
			result.Statistics.FilesScanned++

			content, err := gitRepo.GetFileContent(ctx, commit.Hash, filePath)
			if err != nil {
				logger.Debug(ctx, "Failed to get file content", "file", filePath, "error", err)
				continue
			}

			if content == nil {
				continue
			}

			// Detect secrets
			findings := detector.ScanContent(
				ctx,
				content,
				filePath,
				commit.Hash,
				commit.Author,
				commit.Message,
			)

			if len(findings) > 0 {
				filesWithFindings[filePath] = true
				for _, finding := range findings {
					result.AddFinding(finding)
					logger.Warn(ctx, "Secret detected",
						"type", finding.Type,
						"file", finding.FilePath,
						"severity", finding.Severity,
					)
				}
			}
		}
	}

	result.Statistics.FilesWithFindings = len(filesWithFindings)
	result.Statistics.EndTime = time.Now()
	result.Statistics.ScanDuration = result.Statistics.EndTime.Sub(result.Statistics.StartTime)

	// Validate secrets if validation configs are present
	validateFindings(ctx, result, cfg)

	// Filter inactive secrets and/or validation errors if configured
	if cfg.HideInactiveSecrets || cfg.HideValidationErrors {
		filterInactiveSecrets(ctx, result, cfg.HideInactiveSecrets, cfg.HideValidationErrors)
	}

	// Generate and print report
	return generateAndPrintReport(ctx, result, outputFormat)
}

func validateFindings(ctx context.Context, result *analyzer.ScanResult, cfg *config.Config) {
	if len(result.Findings) == 0 {
		return // Nothing to validate
	}

	// Check if any rule has validation config
	hasValidationConfig := false
	for _, rule := range cfg.Rules {
		if rule.Validation != nil {
			hasValidationConfig = true
			break
		}
	}

	if !hasValidationConfig {
		return // No validation configured
	}

	logger.Info(ctx, "Starting validation of detected secrets", "count", len(result.Findings))

	// Create validator orchestrator
	orchestrator := validator.NewValidatorOrchestrator(5) // 5 parallel workers

	// Build secret info for validation
	secretInfos := make([]validator.SecretInfo, len(result.Findings))
	ruleMap := make(map[string]*config.Rule)
	for i, rule := range cfg.Rules {
		ruleMap[rule.Name] = &cfg.Rules[i]
	}

	for i, finding := range result.Findings {
		secretInfos[i] = validator.SecretInfo{
			Secret:    finding.Value,
			Type:      finding.Rule,
			Masked:    finding.MaskedValue,
			FilePath:  finding.FilePath,
			RuleIndex: i,
		}
	}

	// Run validation
	validationResults := orchestrator.ValidateFindings(ctx, secretInfos, ruleMap)

	// Update findings with validation results
	for idx, valResult := range validationResults {
		if idx >= 0 && idx < len(result.Findings) {
			result.Findings[idx].ValidationStatus = string(valResult.Status)
			result.Findings[idx].ValidationDetails = &analyzer.ValidationDetails{
				Status:       string(valResult.Status),
				Timestamp:    valResult.Timestamp,
				ErrorMessage: valResult.ErrorMessage,
				HTTPStatus:   valResult.HTTPStatus,
				ResponseTime: valResult.ResponseTime,
			}

			// Update statistics
			if valResult.Status != validator.ValidationStatusNotValidated {
				result.Statistics.ValidatedCount++
				switch valResult.Status {
				case validator.ValidationStatusActive:
					result.Statistics.ActiveSecretsCount++
				case validator.ValidationStatusInactive:
					result.Statistics.InactiveSecretsCount++
				case validator.ValidationStatusError:
					result.Statistics.ValidationErrorsCount++
				}
			}

			logger.Info(ctx, "Secret validated",
				"rule", result.Findings[idx].Rule,
				"status", result.Findings[idx].ValidationStatus,
				"file", result.Findings[idx].FilePath,
			)
		}
	}

	logger.Info(ctx, "Validation complete",
		"total_validated", result.Statistics.ValidatedCount,
		"active", result.Statistics.ActiveSecretsCount,
		"inactive", result.Statistics.InactiveSecretsCount,
		"errors", result.Statistics.ValidationErrorsCount,
	)
}

func filterInactiveSecrets(ctx context.Context, result *analyzer.ScanResult, hideInactive, hideErrors bool) {
	// Filter out findings based on validation status
	filteredFindings := make([]analyzer.Finding, 0)
	removedCount := 0
	removedByType := make(map[string]int)
	removedBySeverity := make(map[analyzer.Severity]int)

	for _, finding := range result.Findings {
		shouldFilter := false

		// Check if this finding should be filtered based on validation status
		if hideInactive && finding.ValidationStatus == "inactive" {
			shouldFilter = true
		}
		if hideErrors && finding.ValidationStatus == "error" {
			shouldFilter = true
		}

		if shouldFilter {
			// Track removed findings
			removedCount++
			removedByType[finding.Type]++
			removedBySeverity[finding.Severity]++

			logger.Debug(ctx, "Filtering out secret",
				"rule", finding.Rule,
				"status", finding.ValidationStatus,
				"file", finding.FilePath,
			)
		} else {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	if removedCount > 0 {
		// Update findings list
		result.Findings = filteredFindings

		// Update statistics
		result.Statistics.FindingsCount = len(filteredFindings)

		for typ, count := range removedByType {
			result.Statistics.FindingsByType[typ] -= count
			if result.Statistics.FindingsByType[typ] <= 0 {
				delete(result.Statistics.FindingsByType, typ)
			}
		}

		for sev, count := range removedBySeverity {
			result.Statistics.FindingsBySeverity[sev] -= count
			if result.Statistics.FindingsBySeverity[sev] <= 0 {
				delete(result.Statistics.FindingsBySeverity, sev)
			}
		}

		logger.Info(ctx, "Filtered secrets based on validation status",
			"removed_count", removedCount,
			"remaining", len(filteredFindings),
			"hide_inactive", hideInactive,
			"hide_errors", hideErrors,
		)
	}
}

func generateAndPrintReport(ctx context.Context, result *analyzer.ScanResult, format string) error {
	var reporter report.Reporter

	switch format {
	case "json":
		reporter = report.NewJSONReporter()
	case "text":
		reporter = report.NewTextReporter()
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}

	reportOutput, err := reporter.GenerateReport(result)
	if err != nil {
		logger.Error(ctx, "Failed to generate report", "error", err)
		return fmt.Errorf("failed to generate report: %w", err)
	}

	fmt.Println(reportOutput)

	// Return exit code based on findings
	if result.Statistics.FindingsCount > 0 {
		return fmt.Errorf("secrets detected: %d findings", result.Statistics.FindingsCount)
	}

	return nil
}
