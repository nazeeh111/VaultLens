package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"time"
)

//go:embed report.html
var reportTemplate string

func Render(r Report, format string) ([]byte, error) {
	if format == "json" {
		b, err := json.MarshalIndent(r, "", "  ")
		return append(b, '\n'), err
	}
	if format != "html" {
		return nil, errors.New("format must be json or html")
	}
	t, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = t.Execute(&b, r)
	return b.Bytes(), err
}

// Link publishes a complete synced temporary file without replacing existing data.
func WriteReport(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".vaultlens-*")
	if err != nil {
		return errors.New("cannot create report temporary file")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return errors.New("cannot restrict report permissions")
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return errors.New("cannot write report")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return errors.New("cannot sync report")
	}
	if err = f.Close(); err != nil {
		return errors.New("cannot close report")
	}
	if err = os.Link(tmp, path); err != nil {
		return errors.New("cannot publish report; destination must be new and filesystem must support hard links")
	}
	return nil
}

func run(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("vaultlens", flag.ContinueOnError)
	flags.SetOutput(errOut)
	input := flags.String("input", "", "explicit plaintext JSON export path (never auto-discovered)")
	output := flags.String("out", "", "new report path; existing files are never overwritten")
	format := flags.String("format", "html", "html or json")
	date := flags.String("as-of", time.Now().UTC().Format("2006-01-02"), "audit date YYYY-MM-DD; set for reproducible reports")
	labels := flags.Bool("include-labels", false, "include sensitive titles and usernames; never passwords, original IDs or URIs")
	fail := flags.Bool("fail-on-findings", false, "exit 3 after writing report if any non-informational finding exists")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *input == "" || *output == "" || (*format != "html" && *format != "json") {
		fmt.Fprintln(errOut, "Provide --input and --out; --format must be html or json. Use --help.")
		return 2
	}
	asOf, err := time.Parse("2006-01-02", *date)
	if err != nil {
		fmt.Fprintln(errOut, "Invalid --as-of date; use YYYY-MM-DD.")
		return 2
	}
	info, err := os.Lstat(*input)
	if err != nil || !info.Mode().IsRegular() {
		fmt.Fprintln(errOut, "Input must be an existing regular file, not a symlink or device.")
		return 2
	}
	if info.Size() > MaxBytes {
		fmt.Fprintln(errOut, "Input exceeds 16 MiB limit.")
		return 2
	}
	f, err := os.Open(*input)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot open input.")
		return 2
	}
	ex, err := Parse(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(errOut, "Input rejected:", err)
		return 2
	}
	report, err := Audit(ex, asOf, *labels)
	if err != nil {
		fmt.Fprintln(errOut, "Audit failed.")
		return 2
	}
	data, err := Render(report, *format)
	if err != nil {
		fmt.Fprintln(errOut, "Report rendering failed.")
		return 2
	}
	if err = WriteReport(*output, data); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	fmt.Fprintf(out, "VaultLens: %d items, %d login items, %d findings. Report written; labels included: %t.\n", report.TotalItems, report.LoginItems, len(report.Findings), *labels)
	if *fail {
		for _, finding := range report.Findings {
			if finding.Severity != "info" {
				return 3
			}
		}
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
