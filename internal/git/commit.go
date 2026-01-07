// Package git provides interfaces and implementations for interacting with Git repositories.
package git

import (
	"context"
	"time"
)

// Commit represents a Git commit with its metadata.
type Commit struct {
	Hash      string
	Author    string
	Email     string
	Message   string
	Timestamp time.Time
}

// CommitOptions contains options for retrieving commits.
type CommitOptions struct {
	AllHistory bool   // Scan entire history if true
	LastN      int    // Number of last commits to scan (ignored if AllHistory is true)
	Branch     string // Branch name (empty for current branch)
}

// Repository is the interface for interacting with Git repositories.
type Repository interface {
	// GetCommits retrieves commits according to the provided options.
	GetCommits(ctx context.Context, opts CommitOptions) ([]Commit, error)

	// GetFileContent returns the content of a file at a specific commit.
	GetFileContent(ctx context.Context, commitHash, filePath string) ([]byte, error)

	// GetAffectedFiles returns list of files modified in a commit.
	GetAffectedFiles(ctx context.Context, commitHash string) ([]string, error)

	// Validate checks if the repository is valid and accessible.
	Validate(ctx context.Context) error
}
