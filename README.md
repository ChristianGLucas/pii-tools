# pii-tools

Composable [Axiom](https://axiom.dev) nodes for detecting and anonymizing
personally identifiable information (PII) in free text. Built for the Axiom
marketplace, published under the `christiangeorgelucas` handle.

## What it does

- **Detect** — scan free text for PII entities: email addresses, phone
  numbers, credit card numbers, crypto wallet addresses, IBANs, IP/MAC
  addresses, URLs, dates, and several US-specific identifiers (SSN, ITIN,
  passport, driver's license, bank account, ABA routing number, medical
  license, NPI, MBI).
- **Anonymize** — redact, mask, hash, reversibly encrypt/decrypt, or
  substitute detected (or caller-supplied) entity spans.

Offline and deterministic — no network calls, no external service, no
persisted state.

## What it deliberately does NOT do

This package does **not** detect free-text person names, locations, or
organizations. That requires an NLP/NER model, and every mature, permissively
-licensed option we evaluated (Microsoft Presidio, spaCy, python-stdnum via
`scrubadub`) turned out to mandatorily pull in a copyleft dependency
transitively — see `vendor/presidio_patterns/NOTICE.md` for the full audit.
Rather than ship a non-permissive dependency, this package covers the
regex/checksum-detectable entity surface liberally and leaves NER-based
name/location detection out.

## Nodes

| Node | What it does |
|---|---|
| `DetectPii` | Scan text for PII entities (filterable by type). |
| `RedactText` | Replace entity spans with `<ENTITY_TYPE>` placeholders. |
| `MaskText` | Partially obscure entity spans (e.g. show only last 4 digits). |
| `HashText` | Replace entity spans with a SHA-256/512 digest. |
| `EncryptText` | Replace entity spans with reversible AES ciphertext. |
| `DecryptText` | Reverse a prior `EncryptText` call. |
| `ReplaceText` | Replace entity spans with caller-supplied substitute text. |
| `AnonymizeText` | One-call detect + apply a chosen operator. |
| `ListSupportedEntities` | Catalog of every detectable entity type. |

## What it wraps

- **Detection**: a vendored, license-audited subset of
  [Microsoft Presidio](https://github.com/microsoft/presidio)'s
  `presidio-analyzer` regex/checksum pattern-recognition engine (MIT) — see
  `vendor/presidio_patterns/NOTICE.md` for exactly what's vendored and why —
  plus Google's [`phonenumbers`](https://github.com/google/libphonenumber)
  (Apache-2.0) for phone-number recognition.
- **Anonymization**: the real, pip-installed
  [`presidio-anonymizer`](https://github.com/microsoft/presidio) package
  (MIT; its only dependency is `cryptography`).

## License

MIT — see `LICENSE`. The vendored Presidio subset carries its own upstream
MIT license and notice; see `vendor/presidio_patterns/LICENSE` and
`NOTICE.md`.
