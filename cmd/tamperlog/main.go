// Command tamperlog operates and verifies tamperlog audit trails from the
// shell: install the schema, append test events, write seals, obtain RFC 3161
// anchors, verify online or from an export bundle, export bundles, resync
// sinks and inspect seals and tokens.
//
// Storage is selected with --driver (pgx or sqlite) and --dsn, or with
// --bundle for offline verification. Flags can also be given as environment
// variables named TAMPERLOG_<FLAG>, for example TAMPERLOG_DSN.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
)

// cli is the command tree.
type cli struct {
	LogLevel string `help:"Log level: debug, info, warn, error." default:"info" env:"TAMPERLOG_LOG_LEVEL"`

	Migrate migrateCmd `cmd:"" help:"Install or upgrade the schema."`
	Append  appendCmd  `cmd:"" help:"Append one event (for tests and demonstrations)."`
	Seal    sealCmd    `cmd:"" help:"Write seals of every stream head, once or on an interval."`
	Anchor  anchorCmd  `cmd:"" help:"Obtain RFC 3161 proofs for unanchored seals, once or continuously."`
	Verify  verifyCmd  `cmd:"" help:"Verify anchors, seals, sinks and chain; exit 0 verified, 1 broken, 2 error."`
	Export  exportCmd  `cmd:"" help:"Export records, seals and proofs as an offline bundle."`
	Resync  resyncCmd  `cmd:"" help:"Push seals and proofs the sinks lack."`
	Inspect inspectCmd `cmd:"" help:"Print a seal or an RFC 3161 token."`
	Version versionCmd `cmd:"" help:"Print the version."`
}

// version is set by the build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	var c cli
	k := kong.Parse(&c,
		kong.Name("tamperlog"),
		kong.Description("Tamper-evident audit trails: seal, anchor and verify."),
		kong.UsageOnError(),
		kong.DefaultEnvars("TAMPERLOG"),
	)
	os.Exit(run(k, &c))
}

func run(k *kong.Context, c *cli) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger, err := newLogger(c.LogLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tamperlog:", err)
		return 2
	}
	err = k.Run(&runContext{ctx: ctx, logger: logger})
	var exit *exitError
	switch {
	case err == nil:
		return 0
	case asExit(err, &exit):
		fmt.Fprintln(os.Stderr, "tamperlog:", exit.Error())
		return exit.code
	default:
		fmt.Fprintln(os.Stderr, "tamperlog:", err)
		return 2
	}
}
