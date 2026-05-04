// Package main is the Pulsar cross-runtime KAT oracle.
//
// Emits a single JSON manifest at <out>/cross_runtime_kat.json that ties
// together the three canonical Pulsar KATs (sign, reshare, dkg2) with
// the SHA-256 of each individual KAT file. The C++ side
// (luxcpp/crypto/pulsar/test/cross_runtime_test.cpp) replays each KAT
// in C++ and verifies byte-equality; running this oracle first then
// the C++ test is the "Go → C++" direction of the gate.
//
// Reverse direction (C++ → Go) is handled by:
//   * luxcpp/crypto/pulsar/cmd/cross_runtime_oracle/  (C++ writer)
//   * lux/pulsar/cmd/cross_runtime_verify/           (Go reader)
//
// Determinism is required. Two runs with the same MasterSeed produce
// byte-equal manifests AND byte-equal individual KAT JSON files.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type manifestEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Sha256   string `json:"sha256"`
	NumBytes int64  `json:"num_bytes"`
}

type manifest struct {
	Description string          `json:"description"`
	Direction   string          `json:"direction"`
	Files       []manifestEntry `json:"files"`
}

func sha256File(path string) (string, int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), int64(len(b)), nil
}

func runOracle(cmd string, args []string) error {
	c := exec.Command("go", append([]string{"run", cmd}, args...)...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func main() {
	out := flag.String("out", "", "output directory (creates cross_runtime_kat.json + per-KAT files via the per-KAT oracles)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: cross_runtime_oracle --out <dir>")
		os.Exit(2)
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	// 1. Emit the per-KAT JSONs by invoking each per-KAT oracle.
	if err := runOracle("./cmd/sign_oracle", []string{"--out", *out}); err != nil {
		fmt.Fprintf(os.Stderr, "sign_oracle: %v\n", err)
		os.Exit(1)
	}
	// reshare_oracle and dkg2_oracle don't expose --out; they write to
	// hardcoded locations in luxcpp/crypto. For the cross-runtime gate
	// we hash the canonical paths.
	signPath    := filepath.Join(*out, "sign_kat.json")
	resharePath := "/Users/z/work/luxcpp/crypto/pulsar/test/kat/reshare_kat.json"
	dkg2Path    := "/Users/z/work/luxcpp/crypto/pulsar/dkg2/test/kat/dkg2_kat.json"

	files := []struct {
		name string
		path string
	}{
		{"sign", signPath},
		{"reshare", resharePath},
		{"dkg2", dkg2Path},
	}

	m := manifest{
		Description: "Pulsar cross-runtime KAT manifest. SHA-256 of each canonical Go-emitted KAT JSON. The C++ cross_runtime_test consumes the same paths and asserts byte-equality at every entry; this manifest pins the Go-side bytes so any drift produces a SHA-256 mismatch caught by the gate.",
		Direction:   "go-to-cpp",
	}
	for _, f := range files {
		sum, sz, err := sha256File(f.path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hash %s: %v\n", f.path, err)
			os.Exit(1)
		}
		m.Files = append(m.Files, manifestEntry{
			Name:     f.name,
			Path:     f.path,
			Sha256:   sum,
			NumBytes: sz,
		})
	}

	mPath := filepath.Join(*out, "cross_runtime_kat.json")
	mBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(mPath, mBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s (%d entries)\n", mPath, len(m.Files))
}
