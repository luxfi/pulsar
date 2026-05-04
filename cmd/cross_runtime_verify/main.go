// Package main is the Go-side verifier for the Pulsar cross-runtime
// KAT gate (C++ → Go direction).
//
// Reads a C++-emitted manifest produced by
// luxcpp/crypto/pulsar/cmd/cross_runtime_oracle and confirms that each
// SHA-256 digest in the manifest matches the bytes Go observes for the
// same file path. Mismatch → non-zero exit code.
//
// Usage:
//
//	cross_runtime_verify --manifest <path/to/cross_runtime_kat_cpp.json>
//
// This is the reverse leg of the cross-runtime gate. The forward leg
// (Go → C++) lives in luxcpp/crypto/pulsar/test/cross_runtime_test.cpp;
// CTest target `pulsar_cross_runtime_kat` exercises both directions.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
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

func main() {
	mPath := flag.String("manifest", "", "path to cross-runtime manifest JSON")
	flag.Parse()
	if *mPath == "" {
		fmt.Fprintln(os.Stderr, "usage: cross_runtime_verify --manifest <path>")
		os.Exit(2)
	}

	mBytes, err := os.ReadFile(*mPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read manifest: %v\n", err)
		os.Exit(1)
	}

	var m manifest
	if err := json.Unmarshal(mBytes, &m); err != nil {
		fmt.Fprintf(os.Stderr, "parse manifest: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== cross_runtime_verify (direction=%s) ===\n", m.Direction)
	fmt.Printf("manifest: %s\n", *mPath)
	fmt.Printf("entries:  %d\n\n", len(m.Files))

	failed := 0
	passed := 0
	for _, f := range m.Files {
		b, err := os.ReadFile(f.Path)
		if err != nil {
			fmt.Printf("  [%-8s] FAIL read: %v\n", f.Name, err)
			failed++
			continue
		}
		if int64(len(b)) != f.NumBytes {
			fmt.Printf("  [%-8s] FAIL size: got=%d want=%d\n",
				f.Name, len(b), f.NumBytes)
			failed++
			continue
		}
		sum := sha256.Sum256(b)
		got := hex.EncodeToString(sum[:])
		if got != f.Sha256 {
			fmt.Printf("  [%-8s] FAIL sha256\n    want: %s\n    got:  %s\n",
				f.Name, f.Sha256, got)
			failed++
			continue
		}
		fmt.Printf("  [%-8s] PASS sha256=%s..\n", f.Name, got[:16])
		passed++
	}

	fmt.Printf("\nresult: %d/%d passed\n", passed, passed+failed)
	if failed > 0 {
		os.Exit(1)
	}
}
