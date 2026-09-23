# VaultLens design

An original, local-only Go CLI audits explicitly supplied Bitwarden-compatible plaintext JSON exports and writes a redacted JSON or standalone HTML report. It never locates vault files, logs into a service, uploads data, decrypts a vault, or changes credentials. Development uses synthetic exports only.

Parsing is bounded by bytes, nesting depth, item count and field sizes. Duplicate JSON keys, ambiguous case variants of recognized fields, unpaired UTF-16 escapes and encrypted-export markers are rejected. The Unicode precheck preserves valid pairs and literal backslashes before standard JSON decoding. Unknown export fields are accepted for compatibility but never copied into reports. Only login items are audited; other categories are counted.

Exact password reuse is grouped using a per-run random HMAC-SHA256 key in memory. Neither fingerprints nor passwords enter report objects. Stable ordinal references identify records by default. An explicit `--include-labels` option includes item titles and usernames, never original IDs or URIs. Heuristics identify short/common passwords, insecure HTTP URIs, duplicated export IDs and candidate duplicate logins. Password age is a review prompt, not a recommendation for periodic password rotation.

Reports have deterministic content for a fixed export and `--as-of` date; ephemeral fingerprints do not affect output. Each report is written as an owner-only temporary file, synced, then atomically linked to a new output path without overwriting an existing file. HTML uses Go's escaping template engine, no scripts, no remote resources, and a restrictive Content Security Policy.

Validation covers malicious/malformed JSON, bounds, known fixture findings, secret redaction, HTML escaping, deterministic output and output-file protection. No claims about password cracking resistance, breach status, comprehensive security or secure erasure.
