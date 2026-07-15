package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/backend-developers-ltd/nexus-auth/internal/auth"
	"github.com/backend-developers-ltd/nexus-auth/internal/configuration"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		printUsage()
		return 1
	}

	subcommand := args[0]
	switch subcommand {
	case "run":
		return cmdRun(args[1:])
	case "generate":
		return cmdGenerate(args[1:])
	case "-h", "-help", "--help", "help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", subcommand)
		printUsage()
		return 2
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  nexus-auth run [-listen-addr addr] [-pylon-endpoint url] [-net-uid n]")
	fmt.Println("  nexus-auth generate -ss58-address addr -identity-name name [-output-dir dir] [-pylon-endpoint url] [-algorithm n] [-not-after-days n] [-force-recreate]")
	fmt.Println("")
	fmt.Println("Subcommands:")
	fmt.Println("  run       Start the auth server")
	fmt.Println("  generate  Generate Ed25519 keypair via Pylon and write client.key and client.crt to -output-dir (default ./certs)")
}

func cmdRun(args []string) int {
	// Get base config from defaults and environment
	config := configuration.NewConfig()

	// Parse CLI flags for this subcommand only, then mutate config via setters
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen-addr", "", "Address to listen on (overrides env/default)")
	pylonEndpoint := fs.String("pylon-endpoint", "", "Pylon service endpoint base URL (overrides env/default)")
	netUID := fs.Int("net-uid", -1, "Subnet UID (overrides NEXUS_PYLON_NETUID env var)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *listen != "" {
		config.SetListenAddress(*listen)
	}
	if *pylonEndpoint != "" {
		config.SetPylonEndpoint(*pylonEndpoint)
	}
	if *netUID >= 0 {
		config.SetNetUID(*netUID)
	}
	if config.GetNetUID() < 0 {
		fmt.Fprintln(os.Stderr, "NEXUS_PYLON_NETUID is required (set env var or use -net-uid flag)")
		return 2
	}

	authServer := auth.NewAuth(config)
	if err := authServer.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed to start: %v\n", err)
		return 1
	}
	return 0
}

func cmdGenerate(args []string) int {
	// Get base config from defaults and environment
	config := configuration.NewConfig()

	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	identityName := fs.String("identity-name", "", "The name of the identity to use")
	ss58Address := fs.String("ss58-address", "", "SS58 address to place in certificate Subject Organization (O)")
	algorithm := fs.Int("algorithm", 1, "Algorithm identifier to request from Pylon")
	outputDir := fs.String("output-dir", "./certs", "Directory to write client.key and client.crt")
	notAfterDays := fs.Int("not-after-days", 365*10, "Number of days until certificate expiration (default 3650 days)")
	forceRecreate := fs.Bool("force-recreate", false, "Force re-creation of client.key and client.crt even if they already exist")
	pylonEndpoint := fs.String("pylon-endpoint", "", "Pylon service endpoint base URL (overrides env/default)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*ss58Address) == "" {
		fmt.Fprintln(os.Stderr, "-ss58-address is required")
		fs.Usage()
		return 2
	}
	if *pylonEndpoint != "" {
		config.SetPylonEndpoint(*pylonEndpoint)
	}
	if strings.TrimSpace(*identityName) != "" {
		config.SetIdentityName(*identityName)
	}
	if strings.TrimSpace(config.IdentityName) == "" {
		fmt.Fprintln(os.Stderr, "-identity-name is required (or set NEXUS_PYLON_IDENTITY_NAME)")
		fs.Usage()
		return 2
	}

	a := auth.NewAuth(config)
	if err := a.Generate(*ss58Address, *outputDir, *algorithm, *notAfterDays, *forceRecreate); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate a certificate: %v\n", err)
		return 1
	}
	return 0
}
