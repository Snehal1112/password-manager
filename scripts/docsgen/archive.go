package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const indexRedirect = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta http-equiv="refresh" content="0; url=docs/admin-manual.html"/>
<title>RocketVault Docs</title>
</head><body>
<p>Redirecting to <a href="docs/admin-manual.html">the Administrator Manual</a>&hellip;</p>
</body></html>
`

// resolveVersion returns the explicit version if given, else falls back to
// `git describe`, else "dev" — mirroring how release.yml derives VERSION
// from the pushed tag for local/manual runs.
func resolveVersion(explicit string) string {
	if explicit != "" {
		return explicit
	}
	out, err := exec.Command("git", "-C", repoRoot, "describe", "--tags", "--always", "--dirty").Output()
	if err != nil {
		return "dev"
	}
	return strings.TrimSpace(string(out))
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeChecksum(path string) error {
	sum, err := sha256File(path)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("%s  %s\n", sum, filepath.Base(path))
	return os.WriteFile(path+".sha256", []byte(line), 0o644)
}

func writeTarGz(stageDir, name, tarPath string) error {
	f, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	return filepath.Walk(stageDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(stageDir, path)
		if err != nil {
			return err
		}
		arcName := filepath.Join(name, rel)
		if info.IsDir() {
			if rel == "." {
				arcName = name
			}
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = arcName + "/"
			return tw.WriteHeader(hdr)
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = arcName
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

func writeZip(stageDir, name, zipPath string) error {
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()

	return filepath.Walk(stageDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(stageDir, path)
		if err != nil {
			return err
		}
		w, err := zw.Create(filepath.ToSlash(filepath.Join(name, rel)))
		if err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(w, src)
		return err
	})
}

// packageDocs builds every markdown-derived page fresh, then stages
// admin-manual.html and everything it links to into a self-contained static
// site — preserving the repo's relative directory layout so every relative
// link keeps resolving unchanged — and archives it as .tar.gz and .zip,
// each with a .sha256 checksum, under dist/.
func packageDocs(explicitVersion string) error {
	if err := buildDocs(); err != nil {
		return err
	}

	version := resolveVersion(explicitVersion)
	name := "rocketvault-docs-" + version
	stage := filepath.Join(repoRoot, "dist", name)

	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}

	var relFiles []string
	for _, e := range docsList {
		relFiles = append(relFiles, e.Out)
	}
	relFiles = append(relFiles, extraFiles...)

	for _, rel := range relFiles {
		if err := copyFile(filepath.Join(repoRoot, rel), filepath.Join(stage, rel)); err != nil {
			return fmt.Errorf("copy %s: %w", rel, err)
		}
	}

	if err := os.WriteFile(filepath.Join(stage, "index.html"), []byte(indexRedirect), 0o644); err != nil {
		return err
	}

	distDir := filepath.Join(repoRoot, "dist")
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		return err
	}

	tarPath := filepath.Join(distDir, name+".tar.gz")
	if err := writeTarGz(stage, name, tarPath); err != nil {
		return err
	}
	if err := writeChecksum(tarPath); err != nil {
		return err
	}

	zipPath := filepath.Join(distDir, name+".zip")
	if err := writeZip(stage, name, zipPath); err != nil {
		return err
	}
	if err := writeChecksum(zipPath); err != nil {
		return err
	}

	fmt.Printf("\nPackaged %d files as %s:\n", len(relFiles)+1, name)
	fmt.Println(" ", tarPath)
	fmt.Println(" ", zipPath)
	fmt.Println("\nPreview locally:")
	fmt.Printf("  go run ./scripts/docsgen serve %s\n", stage)
	return nil
}
