// Command docsgen renders RocketVault's supporting markdown docs into HTML
// pages that share docs/assets/doc-theme.css with docs/admin-manual.html,
// and packages the whole docs site into a hostable static bundle. Markdown
// stays the source of truth — rerun `build` after editing any file in
// docsList (docs.go).
//
//	go run ./scripts/docsgen build
//	go run ./scripts/docsgen package [version]
//	go run ./scripts/docsgen serve [dir] [port]
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// resolveCallerPath resolves a relative CLI argument against the directory
// scripts/docs.sh was invoked from (via DOCSGEN_CALLER_DIR), not this
// program's own working directory — the wrapper cd's into scripts/docsgen/
// before running `go run .`, since docsgen is its own module, so a bare
// relative path like "dist/foo" would otherwise resolve against the wrong
// directory. Absolute paths, and runs without the wrapper, pass through
// via filepath's normal behavior.
func resolveCallerPath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if callerDir := os.Getenv("DOCSGEN_CALLER_DIR"); callerDir != "" {
		return filepath.Join(callerDir, p)
	}
	return p
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "build":
		err = buildDocs()
	case "package":
		version := ""
		if len(os.Args) > 2 {
			version = os.Args[2]
		}
		err = packageDocs(version)
	case "serve":
		dir := resolveCallerPath(".")
		if len(os.Args) > 2 {
			dir = resolveCallerPath(os.Args[2])
		}
		port := "8000"
		if len(os.Args) > 3 {
			port = os.Args[3]
		}
		err = serve(dir, port)
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: docsgen build | docsgen package [version] | docsgen serve [dir] [port]")
}

func serve(dir, port string) error {
	addr := "localhost:" + port
	fmt.Printf("Serving %s at http://%s (Ctrl+C to stop)\n", dir, addr)
	return http.ListenAndServe(addr, http.FileServer(http.Dir(dir)))
}
