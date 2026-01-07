// Package git provides implementation for interacting with Git repositories using go-git.
package git

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// binaryExtensions contains extensions of files that should be skipped.
var binaryExtensions = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".gif":  true,
	".pdf":  true,
	".exe":  true,
	".dll":  true,
	".so":   true,
	".zip":  true,
	".gz":   true,
	".tar":  true,
	".bin":  true,
	".o":    true,
	".a":    true,
}

// GitRepository is an implementation of Repository using go-git.
type GitRepository struct {
	repo *git.Repository
	path string
}

// NewGitRepository creates a new GitRepository instance.
func NewGitRepository(path string) (*GitRepository, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	return &GitRepository{
		repo: repo,
		path: path,
	}, nil
}

// Validate checks if the repository is valid.
func (gr *GitRepository) Validate(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	ref, err := gr.repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get repository head: %w", err)
	}

	if ref == nil {
		return fmt.Errorf("repository has no commits")
	}

	return nil
}

// GetCommits retrieves commits according to the provided options.
func (gr *GitRepository) GetCommits(ctx context.Context, opts CommitOptions) ([]Commit, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var ref *plumbing.Reference
	var err error

	if opts.Branch != "" {
		ref, err = gr.repo.Reference(plumbing.NewBranchReferenceName(opts.Branch), true)
	} else {
		ref, err = gr.repo.Head()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get reference: %w", err)
	}

	iter, err := gr.repo.Log(&git.LogOptions{
		From: ref.Hash(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get commit iterator: %w", err)
	}
	defer iter.Close()

	var commits []Commit
	count := 0

	err = iter.ForEach(func(c *object.Commit) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !opts.AllHistory && opts.LastN > 0 && count >= opts.LastN {
			return nil
		}

		commits = append(commits, Commit{
			Hash:      c.Hash.String(),
			Author:    c.Author.Name,
			Email:     c.Author.Email,
			Message:   c.Message,
			Timestamp: c.Author.When,
		})
		count++

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to iterate commits: %w", err)
	}

	return commits, nil
}

// GetAffectedFiles returns the list of files modified in a commit.
func (gr *GitRepository) GetAffectedFiles(ctx context.Context, commitHash string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	hash := plumbing.NewHash(commitHash)
	commit, err := gr.repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object: %w", err)
	}

	parentTree := &object.Tree{}
	if commit.NumParents() > 0 {
		parent, err := commit.Parent(0)
		if err == nil {
			parentTree, _ = parent.Tree()
		}
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get commit tree: %w", err)
	}

	changes, err := object.DiffTree(parentTree, tree)
	if err != nil {
		return nil, fmt.Errorf("failed to diff trees: %w", err)
	}

	var affectedFiles []string
	for _, change := range changes {
		path := change.To.Name
		if !isBinaryFile(path) {
			affectedFiles = append(affectedFiles, path)
		}
	}

	return affectedFiles, nil
}

// GetFileContent returns the content of a file at a specific commit.
func (gr *GitRepository) GetFileContent(ctx context.Context, commitHash, filePath string) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if isBinaryFile(filePath) {
		return nil, nil
	}

	hash := plumbing.NewHash(commitHash)
	commit, err := gr.repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree: %w", err)
	}

	file, err := tree.File(filePath)
	if err != nil {
		return nil, nil // File doesn't exist in this commit
	}

	reader, err := file.Reader()
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %w", err)
	}

	return content, nil
}

// isBinaryFile checks if a file should be skipped based on its extension.
func isBinaryFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return binaryExtensions[ext]
}
