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

	// Generate and print report
	return generateAndPrintReport(ctx, result, outputFormat)
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
