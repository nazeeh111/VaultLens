# Security model

VaultLens analyzes an explicit local plaintext export in one process. It does not log in, discover credentials, upload data, contact saved URLs, decrypt exports, alter credentials, or delete source records. Development and tests use synthetic data only.

## Boundaries

- Input is limited to 16 MiB, nesting depth 32, arrays/items 20,000; login URI lists to 100, password fields to 65,536 bytes, labels/IDs to 4,096 bytes and individual URIs to 8,192 bytes. Parsing rejects duplicate keys, case variants of recognized schema fields, invalid UTF-8, unpaired escaped UTF-16 surrogates, trailing JSON and unsupported/encrypted shapes. Valid surrogate pairs and literal backslash sequences remain supported; unrelated metadata is ignored. JSON null in optional string fields is treated as absent, matching common exports.
- SHA-256 HMACs with an ephemeral random key group exact password reuse; no fingerprints enter the report. This is not a new password-storage algorithm. Passwords and raw JSON exist in process memory. Go's garbage collector does not guarantee secure erasure; crash dumps, swap and a compromised host remain outside the protection boundary.
- Default reports omit credential-bearing source fields. Opt-in labels can themselves contain secrets and must be treated as sensitive. Ordinal record references and findings reveal counts, category, lengths below a threshold, reuse and relationships. Redacted does not mean anonymous.
- HTML is escaped by `html/template`. Reports have no scripts or remote resources, use a restrictive CSP and do not render input as links. A report does not send telemetry.
- Reports use owner-only Unix permissions, temporary-file sync and atomic hard-link publication to a new path. Existing targets and symlinks are never replaced. Directory permissions and the local operating system are trusted; this is not protection against a hostile local administrator. Output publication is atomic, but durability across all filesystem/power-failure behaviors is not guaranteed. The input is not deleted or rewritten.

## Scope limits

Only login-password fields are assessed. Passkeys, SSH keys, identities, cards, notes, custom fields, attachments, recovery codes and TOTP secrets are not audited. No breached-password service, dictionary corpus, crack-time estimate, entropy score, authentication test or comprehensive duplicate detection is provided. A long password can be weak; a short random password may have different properties than a short human choice. HTTP flags and stale metadata require context. Age alone is not a reason for periodic password changes.

If reporting a vulnerability, use the repository's private vulnerability reporting facility when available. Otherwise open a minimal issue requesting a private contact path, without attaching an actual vault, passwords or personal data. This project does not offer a bug bounty or claim an independent security audit.
