// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cli provides the "rt" (ringtail) subcommand for the lux CLI.
// It wires directly to the github.com/luxfi/pulsar/threshold and
// github.com/luxfi/pulsar/dkg packages.
package cli

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/luxfi/pulsar/threshold"
	"github.com/spf13/cobra"
)

// NewCmd returns the "rt" command tree for the lux CLI.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rt",
		Aliases: []string{"ringtail"},
		Short:   "Ringtail threshold signing",
		Long: `The rt (ringtail) command provides tools for Ringtail threshold signing,
a post-quantum threshold signature scheme using Ring-LWE.

Ringtail is part of the triple consensus (BLS + Ringtail + ML-DSA) used
by Lux validators. It provides threshold signatures where t-of-n parties
can cooperatively produce a valid signature without reconstructing the
full private key.

KEY PROPERTIES:

  - Post-quantum secure (lattice-based)
  - t-of-n threshold without trusted dealer (via DKG)
  - Proactive resharing for key rotation
  - Compatible with QuasarCert attestations`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newKeygenCmd())
	cmd.AddCommand(newSignCmd())
	cmd.AddCommand(newVerifyCmd())
	cmd.AddCommand(newReshareCmd())

	return cmd
}

// keygenOutput is the JSON structure written by keygen.
type keygenOutput struct {
	Threshold int    `json:"threshold"`
	Parties   int    `json:"parties"`
	GroupKey  []byte `json:"group_key"`
}

// shareOutput is the JSON structure for each key share.
type shareOutput struct {
	Index    int    `json:"index"`
	GroupKey []byte `json:"group_key"`
}

func newKeygenCmd() *cobra.Command {
	var (
		t      int
		n      int
		output string
	)
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate threshold key shares",
		Long: `Generate t-of-n threshold key shares for Ringtail signing.

Examples:
  lux rt keygen --threshold 3 --parties 5 --output ./shares/
  lux rt keygen --threshold 2 --parties 3`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if t < 1 {
				return fmt.Errorf("--threshold must be >= 1")
			}
			if n < 2 {
				return fmt.Errorf("--parties must be >= 2")
			}
			if t >= n {
				return fmt.Errorf("--threshold must be < --parties")
			}

			fmt.Fprintf(os.Stderr, "Generating %d-of-%d threshold key shares...\n", t, n)

			shares, groupKey, err := threshold.GenerateKeys(t, n, rand.Reader)
			if err != nil {
				return fmt.Errorf("generate keys: %w", err)
			}

			if output == "" {
				output = "."
			}
			if err := os.MkdirAll(output, 0o750); err != nil {
				return fmt.Errorf("create output dir: %w", err)
			}

			gkBytes := groupKey.Bytes()

			// Write group key info
			info := keygenOutput{
				Threshold: t,
				Parties:   n,
				GroupKey:  gkBytes,
			}
			infoData, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal group info: %w", err)
			}
			infoPath := output + "/group.json"
			if err := os.WriteFile(infoPath, infoData, 0o644); err != nil {
				return fmt.Errorf("write group info: %w", err)
			}

			// Write each share
			for i, share := range shares {
				so := shareOutput{
					Index:    share.Index,
					GroupKey: gkBytes,
				}
				data, err := json.MarshalIndent(so, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal share %d: %w", i, err)
				}
				path := fmt.Sprintf("%s/share-%d.json", output, i)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					return fmt.Errorf("write share %d: %w", i, err)
				}
			}

			fmt.Fprintf(os.Stderr, "Generated %d shares -> %s/\n", len(shares), output)
			fmt.Fprintf(os.Stderr, "Group key: %s\n", infoPath)
			return nil
		},
	}
	cmd.Flags().IntVar(&t, "threshold", 0, "Signing threshold (t)")
	cmd.Flags().IntVar(&n, "parties", 0, "Total number of parties (n)")
	cmd.Flags().StringVar(&output, "output", "", "Output directory for key shares (default: current dir)")
	return cmd
}

func newSignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Initiate threshold signing",
		Long: `Initiate a Ringtail threshold signing session.

Requires t-of-n key holders to participate in the 2-round signing protocol:
  Round 1: Each party broadcasts D matrix + MACs
  Round 2: Each party broadcasts z share
  Finalize: Any party aggregates into final signature

Examples:
  lux rt sign --message "hello" --share ./shares/share-0.json
  lux rt sign --tx-file unsigned.tx --share ./shares/share-0.json`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("interactive threshold signing requires a network session; use the SDK for programmatic signing")
		},
	}
	cmd.Flags().String("message", "", "Message to sign (hex or string)")
	cmd.Flags().String("share", "", "Path to key share file")
	return cmd
}

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a Ringtail signature",
		Long: `Verify a Ringtail threshold signature against the group public key.

Examples:
  lux rt verify --signature sig.json --message "hello" --group-key group.json`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("signature verification requires serialized signature format; use the SDK for programmatic verification")
		},
	}
	cmd.Flags().String("signature", "", "Path to signature file")
	cmd.Flags().String("message", "", "Message that was signed")
	cmd.Flags().String("group-key", "", "Path to group key file")
	return cmd
}

func newReshareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reshare",
		Short: "Reshare keys to new committee",
		Long: `Reshare existing key shares to a new committee configuration.

Proactive resharing allows rotating key shares without changing the
group public key. Used for committee membership changes.

Examples:
  lux rt reshare --old-shares ./old/ --new-threshold 3 --new-parties 7`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("resharing requires coordinated multi-party protocol; use the SDK for programmatic resharing")
		},
	}
	cmd.Flags().String("old-shares", "", "Directory containing old key shares")
	cmd.Flags().Int("new-threshold", 0, "New signing threshold")
	cmd.Flags().Int("new-parties", 0, "New total number of parties")
	return cmd
}
