package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxBytes = 16 << 20
const MaxItems = 20000
const MaxDepth = 32

type Login struct {
	Username             string `json:"username"`
	Password             string `json:"password"`
	PasswordRevisionDate string `json:"passwordRevisionDate"`
	URIs                 []struct {
		URI string `json:"uri"`
	} `json:"uris"`
}
type Item struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  int    `json:"type"`
	Login *Login `json:"login"`
}
type Export struct {
	Encrypted bool   `json:"encrypted"`
	Items     []Item `json:"items"`
}
type Finding struct {
	Code        string   `json:"code"`
	Severity    string   `json:"severity"`
	Items       []string `json:"items"`
	Explanation string   `json:"explanation"`
}
type Entry struct {
	Ref      string `json:"ref"`
	Category string `json:"category"`
	Title    string `json:"title,omitempty"`
	Username string `json:"username,omitempty"`
}
type Report struct {
	Schema         string    `json:"schema"`
	AsOf           string    `json:"as_of"`
	LabelsIncluded bool      `json:"labels_included"`
	TotalItems     int       `json:"total_items"`
	LoginItems     int       `json:"login_items"`
	SkippedItems   int       `json:"skipped_items"`
	Entries        []Entry   `json:"entries"`
	Findings       []Finding `json:"findings"`
	Limitations    []string  `json:"limitations"`
}

// Duplicate keys are rejected at every level rather than accepting last-value wins.
func value(d *json.Decoder, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, errors.New("JSON nesting limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return nil, errors.New("invalid JSON")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, errors.New("invalid object")
			}
			k, ok := key.(string)
			if !ok {
				return nil, errors.New("invalid object key")
			}
			if _, exists := m[k]; exists {
				return nil, errors.New("duplicate JSON key")
			}
			v, err := value(d, depth+1)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object")
		}
		return m, nil
	case '[':
		a := []any{}
		for d.More() {
			if len(a) >= MaxItems {
				return nil, errors.New("array item limit exceeded")
			}
			v, err := value(d, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array")
		}
		return a, nil
	default:
		return nil, errors.New("invalid JSON structure")
	}
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject them
// before decoding so distinct malformed passwords cannot become equal.
func validateUnicodeEscapes(b []byte) error {
	invalid := errors.New("invalid Unicode surrogate escape")
	hex4 := func(at int) (uint16, bool) {
		if at+4 > len(b) {
			return 0, false
		}
		var n uint16
		for _, c := range b[at : at+4] {
			n <<= 4
			switch {
			case c >= '0' && c <= '9':
				n |= uint16(c - '0')
			case c >= 'a' && c <= 'f':
				n |= uint16(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				n |= uint16(c - 'A' + 10)
			default:
				return 0, false
			}
		}
		return n, true
	}
	inString := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || b[i] != '\\' {
			continue
		}
		i++ // Consume the escaped character, including escaped quotes/backslashes.
		if i >= len(b) {
			return errors.New("invalid JSON")
		}
		if b[i] != 'u' {
			continue
		} // The JSON decoder validates other escapes.
		n, ok := hex4(i + 1)
		if !ok {
			return errors.New("invalid JSON Unicode escape")
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return invalid
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return invalid
			}
			low, ok := hex4(i + 3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return invalid
			}
			i += 6
		}
	}
	return nil
}

// Go struct decoding folds field-name case. Require canonical spellings for
// recognized schema fields so validation and conversion cannot disagree.
// Unrelated metadata is retained for parsing and ignored during conversion.
func schemaAliases(m map[string]any, canonical ...string) error {
	for key := range m {
		for _, name := range canonical {
			if key != name && strings.EqualFold(key, name) {
				return errors.New("noncanonical schema field name")
			}
		}
	}
	return nil
}

func validateSchemaNames(root map[string]any) error {
	if err := schemaAliases(root, "encrypted", "items", "data"); err != nil {
		return err
	}
	items, _ := root["items"].([]any)
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if err := schemaAliases(item, "id", "name", "type", "login"); err != nil {
			return err
		}
		login, _ := item["login"].(map[string]any)
		if err := schemaAliases(login, "username", "password", "passwordRevisionDate", "uris"); err != nil {
			return err
		}
		uris, _ := login["uris"].([]any)
		for _, rawURI := range uris {
			uri, _ := rawURI.(map[string]any)
			if err := schemaAliases(uri, "uri"); err != nil {
				return err
			}
		}
	}
	return nil
}

func Parse(r io.Reader) (Export, error) {
	var ex Export
	b, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return ex, errors.New("cannot read input")
	}
	if len(b) > MaxBytes {
		return ex, errors.New("input exceeds 16 MiB limit")
	}
	if !utf8.Valid(b) {
		return ex, errors.New("input must be valid UTF-8")
	}
	if err := validateUnicodeEscapes(b); err != nil {
		return ex, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := value(d, 0)
	if err != nil {
		return ex, err
	}
	if _, err = d.Token(); err != io.EOF {
		return ex, errors.New("trailing JSON content")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ex, errors.New("expected export object")
	}
	if err := validateSchemaNames(m); err != nil {
		return ex, err
	}
	if enc, exists := m["encrypted"]; exists && enc != false {
		return ex, errors.New("encrypted or invalid export marker; plaintext JSON only")
	}
	if _, exists := m["data"]; exists {
		return ex, errors.New("encrypted export envelope is unsupported")
	}
	if _, ok := m["items"].([]any); !ok {
		return ex, errors.New("export must contain an items array")
	}
	encoded, _ := json.Marshal(v)
	if err := json.Unmarshal(encoded, &ex); err != nil {
		return Export{}, errors.New("invalid export field types")
	}
	for _, item := range ex.Items {
		if item.Type < 1 || item.Type > 5 {
			return Export{}, errors.New("missing or unsupported item type")
		}
		if len(item.ID) > 4096 || len(item.Name) > 4096 {
			return Export{}, errors.New("item label exceeds limit")
		}
		if item.Login != nil {
			l := item.Login
			if len(l.Password) > 65536 || len(l.Username) > 4096 || len(l.PasswordRevisionDate) > 128 || len(l.URIs) > 100 {
				return Export{}, errors.New("login field limit exceeded")
			}
			for _, u := range l.URIs {
				if len(u.URI) > 8192 {
					return Export{}, errors.New("URI length exceeds limit")
				}
			}
		}
	}
	return ex, nil
}

func Audit(ex Export, asOf time.Time, labels bool) (Report, error) {
	r := Report{Schema: "vaultlens-report-v1", AsOf: asOf.UTC().Format("2006-01-02"), LabelsIncluded: labels, TotalItems: len(ex.Items), Entries: []Entry{}, Findings: []Finding{}, Limitations: []string{
		"Heuristics are review prompts, not crack-time estimates, breach detection, or a security guarantee.",
		"Only login passwords and metadata are audited; cards, identities, notes, passkeys, attachments and custom fields are not assessed.",
		"Password age alone does not establish compromise or require rotation. Missing dates are reported as unknown.",
		"Reports reveal item counts and relationships even when labels are redacted. Protect both export and reports.",
	}}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return r, errors.New("random source unavailable")
	}
	fingerprint := func(parts ...string) string {
		h := hmac.New(sha256.New, key)
		for _, p := range parts {
			fmt.Fprintf(h, "%d:", len(p))
			h.Write([]byte(p))
		}
		return string(h.Sum(nil))
	}
	reuse := map[string][]string{}
	ids := map[string][]string{}
	duplicates := map[string][]string{}
	add := func(code, severity string, refs []string, why string) {
		r.Findings = append(r.Findings, Finding{code, severity, refs, why})
	}
	categories := []string{"", "login", "secure-note", "card", "identity", "ssh-key"}
	for i, item := range ex.Items {
		if item.Type < 1 || item.Type > 5 {
			return r, errors.New("unsupported item type")
		}
		ref := fmt.Sprintf("item-%05d", i+1)
		entry := Entry{Ref: ref, Category: categories[item.Type]}
		if labels {
			entry.Title = item.Name
			if item.Login != nil {
				entry.Username = item.Login.Username
			}
		}
		r.Entries = append(r.Entries, entry)
		if item.ID != "" {
			ids[fingerprint(item.ID)] = append(ids[fingerprint(item.ID)], ref)
		}
		if item.Type != 1 {
			r.SkippedItems++
			continue
		}
		r.LoginItems++
		if item.Login == nil || item.Login.Password == "" {
			add("missing-password", "review", []string{ref}, "No password present; this may be a passkey-only or incomplete login.")
		}
		l := item.Login
		if l == nil {
			l = &Login{}
		}
		if l.Password != "" {
			fp := fingerprint(l.Password)
			reuse[fp] = append(reuse[fp], ref)
			if utf8.RuneCountInString(l.Password) < 12 {
				add("short-password", "review", []string{ref}, "Fewer than 12 Unicode code points. Length alone does not measure guessing resistance.")
			}
			common := map[string]bool{"password": true, "password123": true, "123456": true, "123456789": true, "qwerty": true, "letmein": true, "admin": true}
			if common[strings.ToLower(l.Password)] {
				add("common-password", "high", []string{ref}, "Matches the small built-in common-password list; not a comprehensive breached-password check.")
			}
			if l.PasswordRevisionDate == "" {
				add("password-age-unknown", "info", []string{ref}, "No password revision date in export.")
			} else if t, err := time.Parse(time.RFC3339, l.PasswordRevisionDate); err != nil || !t.Before(asOf.Add(24*time.Hour)) {
				add("invalid-password-date", "review", []string{ref}, "Password revision date is invalid or after the audit date.")
			} else if asOf.Sub(t) > 365*24*time.Hour {
				add("password-age-review", "info", []string{ref}, "Password revision is over 365 days old. Review context; age alone is not a reason to rotate a password.")
			}
		}
		urls := []string{}
		httpFound, invalidFound := false, false
		for _, u := range l.URIs {
			if u.URI == "" {
				continue
			}
			urls = append(urls, u.URI)
			parsed, err := url.Parse(u.URI)
			if err != nil || parsed.Scheme == "" {
				invalidFound = true
				continue
			}
			if strings.EqualFold(parsed.Scheme, "http") {
				httpFound = true
			}
		}
		if httpFound {
			add("insecure-http-uri", "review", []string{ref}, "A saved URI uses unencrypted HTTP. Verify service support before switching to HTTPS.")
		}
		if invalidFound {
			add("unparsed-uri", "info", []string{ref}, "A saved URI is not a parseable absolute URI. Regex or custom matching may be intentional.")
		}
		sort.Strings(urls)
		if len(urls) > 0 && l.Password != "" {
			parts := append([]string{l.Username, l.Password}, urls...)
			df := fingerprint(parts...)
			duplicates[df] = append(duplicates[df], ref)
		}
	}
	grouped := func(m map[string][]string, code, severity, why string) {
		groups := [][]string{}
		for _, refs := range m {
			if len(refs) > 1 {
				groups = append(groups, refs)
			}
		}
		sort.Slice(groups, func(i, j int) bool { return groups[i][0] < groups[j][0] })
		for _, refs := range groups {
			add(code, severity, refs, why)
		}
	}
	grouped(reuse, "password-reuse", "high", "Exact password shared by these entries; fingerprints are used only in memory and excluded from this report.")
	grouped(ids, "duplicate-export-id", "review", "Multiple records carry the same export ID; review the source export before cleanup.")
	grouped(duplicates, "duplicate-login-candidate", "review", "Username, password and sorted nonempty URI list match exactly. Review before deleting; other fields may differ.")
	return r, nil
}
