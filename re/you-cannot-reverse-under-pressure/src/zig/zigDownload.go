package zig

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
)

type zigDownloadInfo struct {
	Tarball string `json:"tarball"`
	Shasum  string `json:"shasum"`
	Size    string `json:"size"`
}

type zigDownloadVersion struct {
	Version          string           `json:"version"`
	Date             string           `json:"date"`
	Docs             string           `json:"docs"`
	StdDocs          string           `json:"stdDocs"`
	Src              *zigDownloadInfo `json:"src"`
	Bootstrap        *zigDownloadInfo `json:"bootstrap"`
	X8664Macos       *zigDownloadInfo `json:"x86_64-macos"`
	Aarch64Macos     *zigDownloadInfo `json:"aarch64-macos"`
	X8664Linux       *zigDownloadInfo `json:"x86_64-linux"`
	Aarch64Linux     *zigDownloadInfo `json:"aarch64-linux"`
	Armv7ALinux      *zigDownloadInfo `json:"armv7a-linux"`
	Riscv64Linux     *zigDownloadInfo `json:"riscv64-linux"`
	Powerpc64LeLinux *zigDownloadInfo `json:"powerpc64le-linux"`
	PowerpcLinux     *zigDownloadInfo `json:"powerpc-linux"`
	X86Linux         *zigDownloadInfo `json:"x86-linux"`
	X8664Windows     *zigDownloadInfo `json:"x86_64-windows"`
	Aarch64Windows   *zigDownloadInfo `json:"aarch64-windows"`
	X86Windows       *zigDownloadInfo `json:"x86-windows"`
}

func (z zigDownloadVersion) getVersionForOsArchPair(os string, arch string) *zigDownloadInfo {
	if os == "darwin" {
		if arch == "amd64" {
			return z.X8664Macos
		} else if arch == "arm64" {
			return z.Aarch64Macos
		} else {
			return nil
		}
	} else if os == "linux" {
		if arch == "amd64" {
			return z.X8664Linux
		} else if arch == "arm64" {
			return z.Aarch64Linux
		} else {
			return nil
		}
	} else if os == "windows" {
		if arch == "amd64" {
			return z.X8664Windows
		} else if arch == "arm64" {
			return z.Aarch64Windows
		} else {
			return nil
		}
	} else {
		return nil
	}
}

type zigDownloadIndex map[string]zigDownloadVersion

func (d *NativeCompileDriver) extractArchive(base string, reader io.Reader, archiveSize int64) (string, error) {
	var zigFilename string

	pb := progressbar.DefaultBytes(archiveSize, "extracting zig")
	defer pb.Close()

	tarReader := tar.NewReader(reader)

	// Extract all the files from the zig archive.
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		filename := filepath.Join(base, hdr.Name)

		if strings.HasSuffix(filename, "/zig") || strings.HasSuffix(filename, "/zig.exe") {
			zigFilename = filename
		}

		pb.Describe(filename)

		if hdr.Typeflag == tar.TypeReg {
			f, err := os.Create(filename)
			if err != nil {
				return "", err
			}
			defer f.Close()

			_, err = io.Copy(io.MultiWriter(f, pb), tarReader)
			if err != nil {
				return "", err
			}
		} else if hdr.Typeflag == tar.TypeDir {
			err := os.MkdirAll(filename, os.ModePerm)
			if err != nil {
				return "", err
			}
		} else {
			return "", fmt.Errorf("type %d not implemented for %s", hdr.Typeflag, filename)
		}

		err = os.Chmod(filename, fs.FileMode(hdr.Mode))
		if err != nil {
			return "", err
		}
	}

	return zigFilename, nil
}

func (d *NativeCompileDriver) ensureZig() error {
	// Early out if we already called ensureZig before.
	if d.zigFilename != "" {
		return nil
	}

	zigPath := "nativeCompile"

	// Early out if the manifest has already been downloaded.
	manifestFile, err := os.Open(filepath.Join(zigPath, "manifest.txt"))
	if err == nil {
		defer manifestFile.Close()

		content, err := io.ReadAll(manifestFile)
		if err != nil {
			return err
		}

		d.zigFilename = string(content)

		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	err = os.MkdirAll(zigPath, os.ModePerm)
	if err != nil {
		return err
	}

	// Download the download index page.
	resp, err := http.Get(downloadIndex)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Decode the JSON from the page.
	var index zigDownloadIndex

	dec := json.NewDecoder(resp.Body)

	err = dec.Decode(&index)
	if err != nil {
		return err
	}

	version, ok := index[zigVersion]
	if !ok {
		return fmt.Errorf("version %s could not be found", zigVersion)
	}

	downloadInfo := version.getVersionForOsArchPair(runtime.GOOS, runtime.GOARCH)
	if downloadInfo == nil {
		return fmt.Errorf("could not find zig for architecture %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	tarball, err := http.Get(downloadInfo.Tarball)
	if err != nil {
		return err
	}
	defer tarball.Body.Close()

	var reader io.Reader = tarball.Body

	if strings.HasSuffix(downloadInfo.Tarball, ".xz") {
		xzReader, err := xz.NewReader(reader)
		if err != nil {
			return err
		}
		reader = xzReader
	}

	d.zigFilename, err = d.extractArchive(zigPath, reader, tarball.ContentLength)
	if err != nil {
		return err
	}

	// Check to make sure we found the executable at some point.
	if d.zigFilename == "" {
		return fmt.Errorf("zig extracted but no executable found")
	}

	slog.Info("found zig executable", "filename", d.zigFilename)

	// write a manifest
	newManifestFile, err := os.Create(filepath.Join(zigPath, "manifest.txt"))
	if err != nil {
		return err
	}
	defer newManifestFile.Close()
	fmt.Fprintf(newManifestFile, "%s", d.zigFilename)

	return nil
}

func EnsureDownloaded() error {
	return (&NativeCompileDriver{}).ensureZig()
}
