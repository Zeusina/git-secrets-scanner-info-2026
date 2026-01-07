// Package logger provides centralized logging functionality for the git-secrets-scanner.
package logger

import (
	"context"
	"log/slog"
	"os"
)

// Logger is the global logger instance for the application.
var Log *slog.Logger

func init() {
	Log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(Log)
}

// SetLevel sets the logging level for the logger.
func SetLevel(level slog.Level) {
	Log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(Log)
}

// Info logs an informational message.
func Info(ctx context.Context, msg string, args ...any) {
	Log.InfoContext(ctx, msg, args...)
}

// Error logs an error message.
func Error(ctx context.Context, msg string, args ...any) {
	Log.ErrorContext(ctx, msg, args...)
}

// Debug logs a debug message.
func Debug(ctx context.Context, msg string, args ...any) {
	Log.DebugContext(ctx, msg, args...)
}

// Warn logs a warning message.
func Warn(ctx context.Context, msg string, args ...any) {
	Log.WarnContext(ctx, msg, args...)
}
