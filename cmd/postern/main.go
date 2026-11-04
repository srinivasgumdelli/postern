// Command postern is the bridge: setup commands, the MCP server for
// agent sessions, and the session-guard hooks.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"postern/internal/cli"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.DefaultEnv(version))
	stop()
	os.Exit(code)
}
