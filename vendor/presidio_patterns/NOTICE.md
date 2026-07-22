# Vendored: Microsoft Presidio (presidio-analyzer), MIT License

This directory vendors a subset of [Microsoft Presidio](https://github.com/microsoft/presidio)'s
`presidio-analyzer` package (v2.2.364), MIT licensed — see `LICENSE` in this
directory (copied verbatim from the upstream repo at the matching tag).

## What's vendored, and why

Only the regex/checksum **pattern-recognizer engine** is vendored: the base
classes (`pattern.py`, `pattern_recognizer.py`, `entity_recognizer.py`,
`local_recognizer.py`, `recognizer_result.py`, `analysis_explanation.py`,
`score_thresholds.py`) plus a curated set of `predefined_recognizers` under
`recognizers/` — copied verbatim from upstream except for the import-path
rewrite described below.

**Why vendor instead of `pip install presidio-analyzer`:** presidio-analyzer's
own `setup.py` unconditionally requires `spacy` (for its NLP-based
PERSON/LOCATION/NRP recognizers) and `tldextract` (used only by its
`EmailRecognizer`, to validate the matched domain's public suffix). Both pull
in `requests`, and `requests` pulls in `certifi`, which is **MPL-2.0**
licensed — copyleft, and this project's license gate rejects any GPL/AGPL/
LGPL/MPL dependency anywhere in the installed closure, even one never
imported at runtime (see this package's retrospective for the full audit —
`pip install presidio-analyzer` pulls certifi in via THREE independent paths:
spacy's own `requests` dependency, spacy's `weasel` -> `httpx` -> `httpcore`,
and presidio-analyzer's own `tldextract` -> `requests-file` -> `requests`).

None of that is needed for the regex/checksum recognizers this package
exposes — they are pure Python + the `regex` package (Apache-2.0/CNRI-Python)
plus, for phone numbers, Google's `phonenumbers` (Apache-2.0). So instead of
installing the real package, the handful of source files that provide that
functionality are copied here directly, with `spacy`/`tldextract`-dependent
recognizers (PERSON, LOCATION, NRP, and upstream's `EmailRecognizer`)
excluded entirely.

## Changes made to the vendored source

1. **Import path**: `from presidio_analyzer import ...` -> `from presidio_patterns
   import ...` (this vendored package is named `presidio_patterns`, not
   `presidio_analyzer`, so it can never collide with a real PyPI install of
   the genuine package).
2. **Dropped the `NlpArtifacts` type-hint import** (`from
   presidio_analyzer.nlp_engine import NlpArtifacts`) from `phone_recognizer.py`
   and `iban_recognizer.py` — used only as an optional parameter's type
   annotation (`nlp_artifacts: NlpArtifacts = None`), never as a runtime
   value; this package always calls recognizers with `nlp_artifacts=None`
   (no NLP-context score boosting), so the annotation is dropped rather than
   pulling in the module that declares it.
3. **`iban_recognizer.py`**'s import of `iban_patterns.py` was rewritten from
   an absolute `presidio_analyzer.predefined_recognizers.generic.iban_patterns`
   path to a same-directory relative import.
4. **`recognizers/email_recognizer.py` is NOT vendored from upstream** — it's
   a from-scratch replacement (see that file's own header) using the same
   regex-based technique Presidio itself uses for its other pattern
   recognizers, without the `tldextract` dependency.
5. **Not vendored at all**: `AnalyzerEngine`, `BatchAnalyzerEngine`,
   `RecognizerRegistry`, the NLP engine subsystem, and every
   spaCy/transformers/stanza-backed recognizer (`SpacyRecognizer`,
   `TransformersRecognizer`, PERSON/LOCATION/NRP support). This package does
   not detect free-text person names, locations, or nationality/religious/
   political-group mentions — see this package's README/retrospective for
   that explicitly scoped limitation.

Everything else — the regex patterns, checksum/validation algorithms (Luhn,
IBAN mod-97, Bech32, ABA routing, NPI's CMS-prefixed Luhn, SSN
invalid-range/placeholder rejection, etc.) — is byte-for-byte Microsoft's
own code, unmodified.
