# VaultLens

**Inspect password hygiene locally. Keep the export off the network.**

VaultLens is an original Go CLI that reads an explicitly selected Bitwarden-compatible plaintext JSON export and creates a redacted JSON or standalone HTML audit. No account, browser extension, server, dependency downloads at runtime, or network client. This is an audit tool, not a password manager or encryption implementation.

[Open the synthetic HTML demo](https://nazeeh111.github.io/VaultLens/), [inspect the synthetic JSON report](docs/synthetic-report.json) or download and open the [standalone HTML report](docs/synthetic-report.html). Neither contains real credentials.

## Run the synthetic demo

Requires Go 1.24+ and a filesystem supporting hard links (tested on macOS; Linux CI configured). No third-party Go dependencies.

```sh
go test -race ./...
go build -trimpath -o vaultlens .
./vaultlens --input testdata/synthetic.json --out demo.html --as-of 2026-09-23
./vaultlens --input testdata/synthetic.json --out demo.json --format json --as-of 2026-09-23
```

Open `demo.html` locally. All fixture credentials are deliberately invented; `example.invalid` is a reserved example domain. The fixture and date make reports reproducible. Existing report paths are never overwritten; choose a new path or manage earlier reports yourself.

## What it checks

| Diagnostic | Meaning |
|---|---|
| Exact password reuse | Groups entries whose passwords are byte-for-byte equal, using per-run HMAC fingerprints only in memory |
| Short/common password | Explicit small heuristics: fewer than 12 Unicode code points or a seven-entry common-password list |
| Duplicate export ID | Flags repeated source IDs without disclosing those IDs |
| Duplicate login candidate | Exact username, password and sorted URI list match; other fields may differ, so deletion is never automatic |
| HTTP URI | Flags a saved unencrypted HTTP address; no URL is contacted or included in the report |
| Password age | Missing, invalid/future, or over-365-day revision date; age is a review prompt, not a requirement to rotate |
| Missing password | May be a passkey-only or incomplete login; not automatically a defect |

Non-login categories are counted and indexed but not audited. Unknown metadata is ignored. See [security model](SECURITY.md) and [design](DESIGN.md).

## Report privacy

Default reports contain ordinal references such as `item-00001`, categories and findings. They omit original IDs, titles, usernames, URLs, notes, passwords and fingerprints. Use the explicit `--include-labels` flag only when a report needs titles/usernames; labels themselves may contain private information. Counts and reuse relationships remain sensitive even in redacted reports.

VaultLens never discovers or reads an existing vault automatically. For an actual audit, supply only an export you are authorized to inspect. [Bitwarden documents JSON and encrypted export formats](https://bitwarden.com/help/export-your-data/); this tool supports only the plaintext `items` JSON shape. It does not decrypt encrypted exports or support CSV/ZIP. Creating a plaintext export creates an additional sensitive copy; prefer the password manager's built-in auditing if that better suits your needs.

## CLI contract

```text
--input PATH          Required regular plaintext JSON file, not a symlink
--out PATH            Required new output file; no overwrite
--format html|json    Default html
--as-of YYYY-MM-DD    Default current UTC date; set for reproducibility
--include-labels      Explicitly include sensitive titles/usernames
--fail-on-findings    Return 3 after saving if high/review findings exist
```

Exit **0** means report written, **2** means usage/input/output failure, **3** means report written with actionable heuristic findings when requested. No raw input values are printed in parse errors. Output files are mode `0600` on Unix systems, written to a temporary file, synced, and atomically published without replacing existing files. Storage that does not support hard links fails safely.

## Verification

```sh
go vet ./...
go test -race -cover ./...
go test -fuzz=FuzzParse -fuzztime=5s
```

Tests cover bounded malformed/adversarial JSON, duplicate keys and schema aliases, UTF-8 and escaped Unicode, wrong types, HTML injection, exact synthetic findings, secret omission, deterministic output, symlinks, atomic no-overwrite behavior and CLI exits. No real vault data was used during development. Passing tests do not establish comprehensive security or crack resistance. See the [local verification record](docs/verification.md) for exact checks and review-driven fixes.

**Publication note:** Built locally using Git before publication. The upload date records publication of this version, not an invented development history.

Original software © 2026 nazeeh111, [MIT](LICENSE). Bitwarden is referenced solely for export-format compatibility; this project is not affiliated with Bitwarden.
