package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// version is set at build time via -ldflags "-X main.version=<git-sha>".
var version = "dev"

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// dispatch routes CLI arguments to a subcommand.
//
// Usage forms:
//
//	identity-server                         → identity serve (default)
//	identity-server identity [flags]        → identity subcommand
//	identity-server config   [flags]        → config subcommand
//	identity-server --reset-admin ...       → identity legacy flags (backward compat)
//	identity-server help | --help | -h      → top-level usage
func dispatch(args []string) error {
	if len(args) == 0 {
		return runIdentity(nil)
	}

	first := args[0]

	if first == "help" || first == "--help" || first == "-h" {
		printTopUsage()
		return nil
	}

	// Legacy flag-style invocation: identity-server --reset-admin, --list-backups, etc.
	// Route to identity subcommand for backward compatibility with existing deploys.
	if strings.HasPrefix(first, "-") {
		return runIdentity(args)
	}

	switch first {
	case "identity":
		return runIdentity(args[1:])
	case "config":
		return runConfig(args[1:])
	default:
		printTopUsage()
		return fmt.Errorf("unknown subcommand: %s", first)
	}
}

func printTopUsage() {
	fmt.Println("Usage: identity-server [subcommand] [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  identity [flags]        Identity service (default if no subcommand given)")
	fmt.Println("  config   [flags]        Config service")
	fmt.Println("  help                    Show this help")
	fmt.Println()
	fmt.Println("For subcommand-specific help: identity-server <subcommand> --help")
	fmt.Println()
	fmt.Println("Legacy top-level identity flags (backward compatibility):")
	fmt.Println("  --reset-admin           Reset the admin password (interactive)")
	fmt.Println("  --rotate-jwt-key        Generate a new JWT signing key")
	fmt.Println("  --clear-prev-jwt-key    Remove the previous JWT key after rotation")
	fmt.Println("  --list-backups          List available R2 backups")
	fmt.Println("  --restore-backup [key]  Restore from an R2 backup (interactive if no key)")
}
