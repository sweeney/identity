package main

import "fmt"

// runConfig dispatches config subcommand flags.
//
// The config service is a separate process that shares this binary with
// identity and uses its own SQLite database and R2 backup prefix. It will
// be wired up in a later milestone; for now this stub exists so the
// dispatcher has a real target to route to and so the usage text is
// discoverable.
func runConfig(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "--help", "-h", "help":
			printConfigUsage()
			return nil
		}
	}
	return fmt.Errorf("config service not yet implemented")
}

func printConfigUsage() {
	fmt.Println("Usage: identity-server config [flags]")
	fmt.Println()
	fmt.Println("The config service stores structured homelab configuration")
	fmt.Println("(key/value namespaces with per-namespace role ACLs).")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  (none)                  Start the config HTTP server")
	fmt.Println("  --help                  Show this help")
	fmt.Println()
	fmt.Println("NOTE: not yet implemented — this is a stub for the dispatcher.")
}
