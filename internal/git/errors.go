// Package git defines errors for the git module.
package git

import "errors"

// Common errors for git operations.
var (
	ErrInvalidRepository = errors.New("invalid git repository")
	ErrNoCommits         = errors.New("repository has no commits")
	ErrCommitNotFound    = errors.New("commit not found")
	ErrFileNotFound      = errors.New("file not found in commit")
)
