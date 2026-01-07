package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/git-secrets-scanner/internal/analyzer"
	"github.com/example/git-secrets-scanner/internal/config"
	gitscan "github.com/example/git-secrets-scanner/internal/git"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestRepository(t *testing.T, path string) *gitscan.GitRepository {
	// Initialize a new repository
	repo, err := git.PlainInit(path, false)
	require.NoError(t, err)

	// Configure user for commits
	cfg, err := repo.Config()
	require.NoError(t, err)
	cfg.User.Name = "Test User"
	cfg.User.Email = "test@example.com"
	err = repo.SetConfig(cfg)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	// Add initial commit with a secret
	secretContent := []byte(`# Configuration file
database_url = "postgres://admin:password123@localhost:5432/mydb"
api_key = "test_secret_1234567890abcdef"
test_token_12345678901234567890ab = "actual_token_value"
`)

	secretFile := filepath.Join(path, "secrets.conf")
	err = os.WriteFile(secretFile, secretContent, 0644)
	require.NoError(t, err)

	_, err = wt.Add("secrets.conf")
	require.NoError(t, err)

	_, err = wt.Commit("Add configuration with secrets", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	// Add another file with different content
	goodContent := []byte(`# Clean configuration
timeout = 30
max_retries = 5
`)

	goodFile := filepath.Join(path, "clean.conf")
	err = os.WriteFile(goodFile, goodContent, 0644)
	require.NoError(t, err)

	_, err = wt.Add("clean.conf")
	require.NoError(t, err)

	_, err = wt.Commit("Add clean configuration", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	gitRepo, err := gitscan.NewGitRepository(path)
	require.NoError(t, err)

	return gitRepo
}

func TestFullScanWithTestRepository(t *testing.T) {
	// Create temporary directory for test repository
	tempDir := t.TempDir()

	// Create test repository with secrets
	gitRepo := createTestRepository(t, tempDir)

	// Create test configuration
	cfg := &config.Config{
		Rules: []config.Rule{
			{
				Name:      "Database URL",
				Pattern:   `(postgres|mysql)://[a-zA-Z0-9_]+:[^\s@]+@[\w\-\.]+`,
				Keywords:  []string{"database", "db_url", "postgres", "mysql"},
				Priority:  "high",
				MinLength: 20,
			},
			{
				Name:      "Test Secret",
				Pattern:   `test_secret_[a-zA-Z0-9]{16}`,
				Keywords:  []string{"secret"},
				Priority:  "high",
				MinLength: 20,
			},
			{
				Name:      "Test Token",
				Pattern:   `test_token_[a-zA-Z0-9]{20}`,
				Keywords:  []string{"token"},
				Priority:  "high",
				MinLength: 25,
			},
		},
		FalsePositives: config.FalsePositives{
			Keywords: []string{},
			Patterns: []string{},
		},
	}

	// Create detector
	detector, err := analyzer.NewSecretDetector(cfg)
	require.NoError(t, err)

	// Validate repository
	ctx := context.Background()
	err = gitRepo.Validate(ctx)
	assert.NoError(t, err)

	// Get commits
	commits, err := gitRepo.GetCommits(ctx, gitscan.CommitOptions{
		AllHistory: true,
	})
	require.NoError(t, err)
	assert.Greater(t, len(commits), 0)

	// Scan commits
	result := &analyzer.ScanResult{
		Statistics: analyzer.Statistics{
			StartTime:          time.Now(),
			FindingsByType:     make(map[string]int),
			FindingsBySeverity: make(map[analyzer.Severity]int),
		},
	}

	for _, commit := range commits {
		affectedFiles, err := gitRepo.GetAffectedFiles(ctx, commit.Hash)
		require.NoError(t, err)

		for _, filePath := range affectedFiles {
			result.Statistics.FilesScanned++

			content, err := gitRepo.GetFileContent(ctx, commit.Hash, filePath)
			require.NoError(t, err)

			if content == nil {
				continue
			}

			findings := detector.ScanContent(
				ctx,
				content,
				filePath,
				commit.Hash,
				commit.Author,
				commit.Message,
			)

			for _, finding := range findings {
				result.AddFinding(finding)
			}
		}
	}

	// Assertions
	result.Statistics.CommitsScanned = len(commits)
	result.Statistics.EndTime = time.Now()

	// We should have found at least one secret
	assert.Greater(t, result.Statistics.FindingsCount, 0, "Should detect at least one secret")

	// Check for specific findings
	foundDatabase := false
	foundSecret := false

	for _, finding := range result.Findings {
		if finding.Type == "Database URL" {
			foundDatabase = true
		}
		if finding.Type == "Test Secret" {
			foundSecret = true
		}
	}

	assert.True(t, foundDatabase, "Should detect database URL")
	assert.True(t, foundSecret, "Should detect test secret")
}

func TestRepositoryCommitRetrieval(t *testing.T) {
	tempDir := t.TempDir()
	gitRepo := createTestRepository(t, tempDir)

	ctx := context.Background()

	// Test getting all commits
	commits, err := gitRepo.GetCommits(ctx, gitscan.CommitOptions{
		AllHistory: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, len(commits))

	// Test getting last N commits
	commits, err = gitRepo.GetCommits(ctx, gitscan.CommitOptions{
		AllHistory: false,
		LastN:      1,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, len(commits))
}

func TestFileContentRetrieval(t *testing.T) {
	tempDir := t.TempDir()
	gitRepo := createTestRepository(t, tempDir)

	ctx := context.Background()

	commits, err := gitRepo.GetCommits(ctx, gitscan.CommitOptions{
		AllHistory: true,
	})
	require.NoError(t, err)
	require.Greater(t, len(commits), 0)

	// Get content of secrets.conf from first commit
	content, err := gitRepo.GetFileContent(ctx, commits[0].Hash, "secrets.conf")
	require.NoError(t, err)
	assert.NotNil(t, content)
	assert.Contains(t, string(content), "database_url")
}
