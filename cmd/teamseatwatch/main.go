package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/teamseatwatch/teamseatwatch/internal/app"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) != 2 {
		logger.Error("invalid_command", "code", "invalid_command")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, os.Args[1], os.Getenv, logger); err != nil {
		logger.Error("startup_failed", "code", app.ErrorCode(err), "role", os.Args[1])
		os.Exit(1)
	}
}
