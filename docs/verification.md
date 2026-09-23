# Local verification

Verified September 23, 2026, on macOS arm64 using Go 1.27.1. Development and review used only invented fixtures, never an actual vault.

- `go vet ./...`: passed.
- `go test -race -cover ./...`: passed, 22 named tests, 87.3% statement coverage.
- `go test -run '^$' -fuzz=FuzzParse -fuzztime=5s -parallel=2`: passed, 18,572 executions in approximately six seconds. A short fuzz run is bounded sampling, not exhaustive validation.
- `go build -trimpath`: passed.
- `gofmt -l` on all Go sources: no unformatted files.
- Actual CLI checks confirmed default field redaction, escaped opted-in HTML labels, owner-only `0600` output, refusal to replace existing files, generic parse errors, and rejection at configured size/depth/array bounds.

## Review-driven fixes

Three reproducible issues were addressed before publication:

1. Go's JSON decoder replaces unpaired escaped UTF-16 surrogates with a replacement character. Two different malformed password strings could therefore trigger a false exact-reuse finding. A bounded precheck now rejects lone or mismatched surrogate escapes in strings and keys before decoding. Valid pairs, literal backslashes and ordinary Unicode remain supported.
2. Go's struct decoding accepts case-folded field aliases while the export-envelope checks used exact names. An uppercase `Encrypted` marker could evade the plaintext-only gate, and case-variant duplicates were ambiguous. Recognized fields now require canonical spellings at the root, item, login and URI levels. Unrelated metadata remains accepted and ignored.
3. The HTML footer previously promised that a report contained no passwords even when explicitly included labels could themselves contain secrets. It now distinguishes omitted password fields/fingerprints from potentially sensitive opt-in labels.

The regression tests failed on the previous implementation and passed after the fixes. Rebuilt CLI probes reject all four reproductions with exit 2, constant-value error messages and no report creation. The shipped synthetic HTML report was regenerated from the fixed binary; the synthetic JSON findings remain unchanged.

## Limits

No guarantee of comprehensive security, secure memory erasure, password strength or breach detection is implied. Linux CI and other Go versions were not executed on this machine. Local directory/OS trust assumptions and plaintext-export risks remain as documented in [the security model](../SECURITY.md).
