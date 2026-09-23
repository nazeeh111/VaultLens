package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) Export {
	t.Helper()
	b, err := os.ReadFile("testdata/synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	x, err := Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return x
}
func date() time.Time { return time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC) }
func TestSyntheticFindings(t *testing.T) {
	r, err := Audit(fixture(t), date(), false)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]int{}
	for _, f := range r.Findings {
		codes[f.Code]++
		if f.Code == "password-reuse" && len(f.Items) != 3 {
			t.Fatal("reuse group")
		}
	}
	for _, c := range []string{"password-reuse", "duplicate-export-id", "duplicate-login-candidate", "insecure-http-uri", "password-age-review", "common-password", "missing-password"} {
		if codes[c] == 0 {
			t.Errorf("missing %s", c)
		}
	}
	if r.TotalItems != 6 || r.LoginItems != 5 || r.SkippedItems != 1 {
		t.Fatal("counts")
	}
}
func TestDeterminismAndNoSecrets(t *testing.T) {
	ex := fixture(t)
	a, _ := Audit(ex, date(), false)
	b, _ := Audit(ex, date(), false)
	aj, _ := Render(a, "json")
	bj, _ := Render(b, "json")
	if !bytes.Equal(aj, bj) {
		t.Fatal("randomness changed public report")
	}
	for _, format := range []string{"json", "html"} {
		data, err := Render(a, format)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"password123", "demonstration-only-cedar-sky-47", "demo@example.invalid", "synthetic-a", "Synthetic mail", "mail.example.invalid", "not-a-real-secret"} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("%s leaked field", format)
			}
		}
	}
}
func TestEscapingAndExplicitLabels(t *testing.T) {
	ex := fixture(t)
	ex.Items[0].Name = `<script>alert("x")</script>`
	ex.Items[0].Login.Username = `<img src=x onerror=alert(1)>`
	r, _ := Audit(ex, date(), true)
	html, _ := Render(r, "html")
	if bytes.Contains(html, []byte("<script>")) || bytes.Contains(html, []byte("<img src=x")) {
		t.Fatal("HTML injection")
	}
	if !bytes.Contains(html, []byte("&lt;script&gt;")) {
		t.Fatal("missing escaped label")
	}
	j, _ := Render(r, "json")
	var decoded Report
	if err := json.Unmarshal(j, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Entries[0].Title != ex.Items[0].Name {
		t.Fatal("explicit labels lost")
	}
	if bytes.Contains(j, []byte("password123")) {
		t.Fatal("password leaked")
	}
}
func TestRejectedJSON(t *testing.T) {
	cases := []string{
		``, `[]`, `null`, `{}`, `{"items":null}`, `{"items":{}}`, `{"encrypted":true,"items":[]}`, `{"encrypted":null,"items":[]}`, `{"data":"ciphertext","items":[]}`, `{"items":[],"items":[]}`, `{"items":[],"\u0069tems":[]}`, `{"items":[]} {}`, `{"items":[null]}`, `{"items":[{"type":1,"type":2}]}`, `{"items":[{"type":1,"login":{"password":123}}]}`, `{"items":[{"type":99}]}`, `{"items":[{"type":1.1}]}`, `{"items":[{"type":1,"login":{"password":"x","uris":"bad"}}]}`,
	}
	for i, s := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := Parse(strings.NewReader(s)); err == nil {
				t.Fatal("accepted invalid export")
			}
		})
	}
	if _, err := Parse(bytes.NewReader([]byte{'{', '"', 0xff, '"', ':', '0', '}'})); err == nil {
		t.Fatal("invalid UTF8")
	}
}
func TestBounds(t *testing.T) {
	cases := []string{strings.Repeat(" ", MaxBytes+1), `{"items":[],"deep":` + strings.Repeat("[", MaxDepth+1) + "0" + strings.Repeat("]", MaxDepth+1) + "}", `{"items":[` + strings.Repeat(`{"type":2},`, MaxItems) + `{"type":2}]}`, `{"items":[{"type":1,"login":{"password":"` + strings.Repeat("x", 65537) + `"}}]}`}
	for i, s := range cases {
		if _, err := Parse(strings.NewReader(s)); err == nil {
			t.Fatalf("bound %d accepted", i)
		}
	}
}
func TestMissingOptionalFields(t *testing.T) {
	ex, err := Parse(strings.NewReader(`{"items":[{"type":1},{"type":1,"login":{"password":null}},{"type":3}],"folders":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := Audit(ex, date(), false)
	if len(r.Findings) != 2 {
		t.Fatal("missing-password cases")
	}
}
func TestDatesAndURIs(t *testing.T) {
	ex := fixture(t)
	l := ex.Items[0].Login
	l.PasswordRevisionDate = "bad"
	l.URIs[0].URI = "not a url"
	r, _ := Audit(ex, date(), false)
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.Code] = true
	}
	if !seen["invalid-password-date"] || !seen["unparsed-uri"] {
		t.Fatal("date/uri diagnostics")
	}
}
func TestAtomicNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := WriteReport(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(path, []byte("second")); err == nil {
		t.Fatal("overwrote existing")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "first" {
		t.Fatal("changed existing")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("permissions")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatal("temporary files leaked")
	}
}
func TestCLIAndExitCodes(t *testing.T) {
	dir := t.TempDir()
	var out, errs bytes.Buffer
	args := []string{"--input", "testdata/synthetic.json", "--out", filepath.Join(dir, "report.html"), "--as-of", "2026-09-23", "--fail-on-findings"}
	if code := run(args, &out, &errs); code != 3 {
		t.Fatalf("code %d: %s", code, errs.String())
	}
	if strings.Contains(out.String(), "password123") || strings.Contains(errs.String(), "password123") {
		t.Fatal("log leaked")
	}
	if code := run(args, &out, &errs); code != 2 {
		t.Fatal("overwrite should fail")
	}
	if code := run([]string{"--input", "missing", "--out", filepath.Join(dir, "x")}, &out, &errs); code != 2 {
		t.Fatal("missing input")
	}
}
func TestInvalidInputErrorDoesNotEchoSecret(t *testing.T) {
	secret := "NEVER-ECHO-THIS"
	_, err := Parse(strings.NewReader(`{"items":[{"type":"` + secret + `"}]}`))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("unsafe error")
	}
}
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"items":[]}`))
	f.Add([]byte(`{"encrypted":true}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 100000 {
			return
		}
		ex, err := Parse(bytes.NewReader(b))
		if err == nil {
			if _, err = Audit(ex, date(), false); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestPasswordlessURLStillAudited(t *testing.T) {
	ex, err := Parse(strings.NewReader(`{"items":[{"type":1,"login":{"uris":[{"uri":"http://example.invalid"}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := Audit(ex, date(), false)
	if len(r.Findings) != 2 || r.Findings[1].Code != "insecure-http-uri" {
		t.Fatal("passwordless URL skipped")
	}
}
func TestSymlinkInputAndOutputProtection(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "export.json")
	if err := os.WriteFile(src, []byte(`{"items":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(src, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	var out, errs bytes.Buffer
	if code := run([]string{"--input", link, "--out", filepath.Join(dir, "report.json")}, &out, &errs); code != 2 {
		t.Fatal("input symlink accepted")
	}
	if err := WriteReport(link, []byte("changed")); err == nil {
		t.Fatal("output symlink replaced")
	}
	b, _ := os.ReadFile(src)
	if string(b) != `{"items":[]}` {
		t.Fatal("source changed")
	}
}
func TestEmptyExportAndInvalidRender(t *testing.T) {
	ex, err := Parse(strings.NewReader(`{"items":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Audit(ex, date(), false)
	if err != nil || len(r.Findings) != 0 {
		t.Fatal("empty export")
	}
	if _, err = Render(r, "xml"); err == nil {
		t.Fatal("format accepted")
	}
	if _, err = Audit(Export{Items: []Item{{Type: 99}}}, date(), false); err == nil {
		t.Fatal("invalid direct audit")
	}
}
func TestFutureDate(t *testing.T) {
	ex := fixture(t)
	ex.Items[0].Login.PasswordRevisionDate = "2026-09-24T00:00:00Z"
	r, _ := Audit(ex, date(), false)
	for _, f := range r.Findings {
		if f.Code == "invalid-password-date" && f.Items[0] == "item-00001" {
			return
		}
	}
	t.Fatal("future date accepted")
}

func TestDuplicateCandidateIncludesUnparsedURIs(t *testing.T) {
	ex, err := Parse(strings.NewReader(`{"items":[{"type":1,"login":{"password":"demo-only","uris":[{"uri":"https://example.invalid"},{"uri":"invalid-a"}]}},{"type":1,"login":{"password":"demo-only","uris":[{"uri":"https://example.invalid"},{"uri":"invalid-b"}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := Audit(ex, date(), false)
	for _, f := range r.Findings {
		if f.Code == "duplicate-login-candidate" {
			t.Fatal("different URI lists grouped")
		}
	}
}
func TestHelp(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"--help"}, &out, &errs); code != 0 {
		t.Fatal("help exit")
	}
}

func TestRejectUnpairedSurrogateEscapes(t *testing.T) {
	for _, escape := range []string{`\ud800`, `\udfff`, `\ud800\ud800`, `\ud800x`, `\udc00\ud800`, `\ud800\\udc00`} {
		input := `{"items":[{"type":1,"login":{"password":"SYNTHETIC_PRIVATE_` + escape + `"}}]}`
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Errorf("accepted malformed surrogate sequence %q", escape)
		} else if strings.Contains(err.Error(), "SYNTHETIC_PRIVATE") {
			t.Fatal("Unicode error disclosed input")
		}
	}
	for _, input := range []string{
		`{"items":[],"\ud800":1}`,
		`{"items":[],"unknown":{"text":"\udfff"}}`,
	} {
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Fatal("accepted malformed surrogate in key or metadata")
		}
	}
}

func TestValidUnicodeAndLiteralEscapesRemainDistinct(t *testing.T) {
	input := `{"items":[{"type":1,"login":{"password":"prefix-\ud83d\ude00"}},{"type":1,"login":{"password":"prefix-😀"}},{"type":1,"login":{"password":"prefix-\\ud83d\\ude00"}}],"unknown":{"text":"\u0022quoted\u0022"}}`
	ex, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if ex.Items[0].Login.Password != ex.Items[1].Login.Password || ex.Items[0].Login.Password == ex.Items[2].Login.Password {
		t.Fatal("valid Unicode pair or literal escape decoded incorrectly")
	}
	r, err := Audit(ex, date(), false)
	if err != nil {
		t.Fatal(err)
	}
	groups := 0
	for _, finding := range r.Findings {
		if finding.Code == "password-reuse" {
			groups++
			if len(finding.Items) != 2 || finding.Items[0] != "item-00001" || finding.Items[1] != "item-00002" {
				t.Fatal("literal escape falsely grouped with Unicode character")
			}
		}
	}
	if groups != 1 {
		t.Fatal("equivalent valid Unicode forms were not grouped")
	}
}

func TestRejectSchemaCaseAliases(t *testing.T) {
	cases := []string{
		`{"Encrypted":true,"items":[]}`,
		`{"encrypted":false,"ENCRYPTED":true,"items":[]}`,
		`{"Data":"SYNTHETIC_CIPHERTEXT","items":[]}`,
		`{"items":[],"Items":[{"type":1}]}`,
		`{"items":[{"Type":1}]}`,
		`{"items":[{"type":1,"Name":"alias"}]}`,
		`{"items":[{"type":1,"ID":"alias"}]}`,
		`{"items":[{"type":1,"Login":{"password":"different"}}]}`,
		`{"items":[{"type":1,"login":{"Password":"different","password":"canonical"}}]}`,
		`{"items":[{"type":1,"login":{"paſſword":"unicode-case-fold"}}]}`,
		`{"items":[{"type":1,"login":{"Username":"alias"}}]}`,
		`{"items":[{"type":1,"login":{"passwordrevisiondate":"2026-09-23T00:00:00Z"}}]}`,
		`{"items":[{"type":1,"login":{"URIs":[]}}]}`,
		`{"items":[{"type":1,"login":{"uris":[{"URI":"https://example.invalid"}]}}]}`,
	}
	for i, input := range cases {
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Errorf("accepted schema case alias case %d", i)
		}
	}
}

func TestUnknownMetadataRemainsIgnored(t *testing.T) {
	input := `{"items":[{"type":1,"name":"canonical","login":{"password":"demonstration-only","passwordRevisionDate":"2026-09-23T00:00:00Z","uris":[{"uri":"https://example.invalid","match":2}],"customMetadata":{"Password":"ignored"}},"unknown":{"Type":"ignored"}}],"metadata":{"Encrypted":true,"Items":"ignored"}}`
	ex, err := Parse(strings.NewReader(input))
	if err != nil || len(ex.Items) != 1 || ex.Items[0].Login.Password != "demonstration-only" {
		t.Fatalf("unknown metadata affected schema decoding: %v", err)
	}
}

func TestUnicodeRejectionCLIProducesNoReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.json")
	if err := os.WriteFile(path, []byte(`{"items":[{"type":1,"login":{"password":"SYNTHETIC_SECRET_\ud800"}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	destination := filepath.Join(dir, "report.json")
	if code := run([]string{"--input", path, "--out", destination, "--format", "json"}, &out, &errs); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("invalid input produced a report")
	}
	if strings.Contains(out.String()+errs.String(), "SYNTHETIC_SECRET") {
		t.Fatal("CLI disclosed invalid string")
	}
}

func TestOptInReportDoesNotPromiseSecretFreeLabels(t *testing.T) {
	ex := fixture(t)
	ex.Items[0].Name = ex.Items[0].Login.Password
	r, err := Audit(ex, date(), true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Render(r, "html")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("This report contains no passwords")) {
		t.Fatal("unconditional password omission claim contradicts opted-in labels")
	}
	if !bytes.Contains(data, []byte("Opt-in labels may contain secrets")) {
		t.Fatal("missing label confidentiality caveat")
	}
}
