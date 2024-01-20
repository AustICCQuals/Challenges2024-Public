package zig

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
)

const (
	downloadIndex = "https://ziglang.org/download/index.json"
	zigVersion    = "0.11.0"
)

type Language string

const (
	LanguageC         Language = "c"
	LanguageCPlusPlus Language = "c++"
)

type OperatingSystem string

const (
	OSLinux        OperatingSystem = "linux"
	OSMacOS        OperatingSystem = "macos"
	OSWASI         OperatingSystem = "wasi"
	OSFreestanding OperatingSystem = "freestanding"
)

type Architecture string

const (
	ArchX8664  Architecture = "x86_64"
	ArchARM64  Architecture = "aarch64"
	ArchWASM32 Architecture = "wasm32"
)

type ApplicationBinaryInterface string

const (
	ABIMusl ApplicationBinaryInterface = "musl"
	ABINone ApplicationBinaryInterface = "none"
)

type TargetDescription struct {
	Arch Architecture
	Os   OperatingSystem
	ABI  ApplicationBinaryInterface
}

func (desc TargetDescription) String() string {
	return fmt.Sprintf("%s-%s-%s", desc.Arch, desc.Os, desc.ABI)
}

func TargetFor(os OperatingSystem, arch Architecture, abi ApplicationBinaryInterface) TargetDescription {
	return TargetDescription{
		Arch: arch,
		Os:   os,
		ABI:  abi,
	}
}

type CompileOptions struct {
	Language        Language
	Target          TargetDescription
	OutputFile      string
	InputFiles      []string
	AdditionalFiles []string
	OpenFile        func(name string) (io.ReadCloser, error)
}

type NativeCompileDriver struct {
	zigFilename string
}

func (d *NativeCompileDriver) Compile(opts CompileOptions) error {
	err := d.ensureZig()
	if err != nil {
		return err
	}

	var zigArgs []string

	if opts.Language == LanguageC {
		zigArgs = append(zigArgs, "cc")
	} else if opts.Language == LanguageCPlusPlus {
		zigArgs = append(zigArgs, "c++")
	} else {
		return fmt.Errorf("language %s not recognized", opts.Language)
	}

	// Add the target.
	zigArgs = append(zigArgs, "-target", opts.Target.String())

	zigArgs = append(zigArgs, "-o", opts.OutputFile)

	zigArgs = append(zigArgs, "-shared")

	// Add the input files.
	zigArgs = append(zigArgs, opts.InputFiles...)

	slog.Debug("run zig", "filename", d.zigFilename, "args", zigArgs)
	cmd := exec.Command(d.zigFilename, zigArgs...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
