package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/theopenlane/iam/tokens"
)

func main() {
	app := &cli.Command{
		Name:  "apitokenkey",
		Usage: "Generate opaque API token key material for configuration-driven rotation",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "output the generated key material as JSON",
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			version, secret, err := tokens.GenerateAPITokenKeyMaterial()
			if err != nil {
				return err
			}

			encodedSecret := base64.StdEncoding.EncodeToString(secret)

			jsonOutput := cmd.Bool("json")
			if !jsonOutput {
				if v, ok := os.LookupEnv("API_TOKEN_KEY_JSON"); ok && v != "" && v != "0" && v != "false" {
					jsonOutput = true
				}
			}

			if jsonOutput {
				payload := map[string]string{
					"version": version,
					"secret":  encodedSecret,
				}

				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")

				return enc.Encode(payload)
			}

			fmt.Println("Generated API token key material")
			fmt.Println()
			fmt.Printf("Version (ULID): %s\n", version)
			fmt.Printf("Secret (base64): %s\n", encodedSecret)
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Println("  1. Add the following entry to your tokens configuration (mark as active):")
			fmt.Println("     - version:", version)
			fmt.Println("       status: active")
			fmt.Println("       secret:", encodedSecret)
			fmt.Println("  2. Demote the previously active key to status: deprecated.")
			fmt.Println("  3. Update your ExternalSecret or environment variables and redeploy the service.")
			fmt.Println("  4. Existing token hashes remain valid; they can be rehashed lazily using HashAPITokenComponents when tokens are presented.")

			return nil
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
