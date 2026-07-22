"""Shared PII detection + anonymization helpers used by every node.

Detection: a vendored subset of Microsoft Presidio's regex/checksum pattern
recognizers (vendor/presidio_patterns — see NOTICE.md there for why this is
vendored rather than `pip install presidio-analyzer`).

Anonymization: the real, pip-installed `presidio-anonymizer` package (MIT,
its only dependency is `cryptography`) — its AnonymizerEngine/DeanonymizeEngine
already implement conflict resolution and every operator (redact/replace/
mask/hash/encrypt/decrypt) correctly and are reused as-is, not reimplemented.
"""

import os
import sys

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_VENDOR_DIR = os.path.join(_PKG_ROOT, "vendor")
if _VENDOR_DIR not in sys.path:
    sys.path.insert(0, _VENDOR_DIR)

from presidio_patterns.recognizers import REGISTRY  # noqa: E402 (after sys.path insert)

from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine  # noqa: E402
from presidio_anonymizer.entities import (  # noqa: E402
    OperatorConfig,
    OperatorResult,
)
from presidio_anonymizer.entities import RecognizerResult as AnonRecognizerResult  # noqa: E402

# Input -> cost bound: caps regex work and the size of every response, applied
# to the RAW input before any recognizer runs.
MAX_TEXT_CHARS = 200_000

_anon_engine = AnonymizerEngine()
_deanon_engine = DeanonymizeEngine()

# One instantiated recognizer per entity type, built once at import time (the
# vendored recognizers are stateless regex/checksum objects — safe to reuse
# across every invocation of every node in this process).
_RECOGNIZERS = {
    entity_type: recognizer_cls()
    for entity_type, (recognizer_cls, _category, _desc, _example) in REGISTRY.items()
}


class PiiError(Exception):
    """A structured, expected error — malformed input, not a crash."""


def _check_text(text, field_name="text"):
    if text is None:
        raise PiiError(f"{field_name} is required")
    if len(text) > MAX_TEXT_CHARS:
        raise PiiError(
            f"{field_name} is {len(text)} chars, over the {MAX_TEXT_CHARS}-char limit"
        )


def _resolve_entity_types(entity_types):
    """Validate a caller-supplied entity_types filter; empty means 'all'."""
    if not entity_types:
        return list(REGISTRY.keys())
    unknown = sorted(set(entity_types) - set(REGISTRY.keys()))
    if unknown:
        raise PiiError(
            f"unknown entity_types: {unknown}. "
            f"See ListSupportedEntities for valid values."
        )
    return list(entity_types)


def supported_entities(category=None):
    """Return the ListSupportedEntities catalog, optionally filtered by category."""
    if category and category not in ("generic", "us"):
        raise PiiError(f"unknown category: {category!r} (expected 'generic' or 'us')")
    out = []
    for entity_type, (_cls, cat, desc, example) in sorted(REGISTRY.items()):
        if category and cat != category:
            continue
        out.append(
            {
                "entity_type": entity_type,
                "description": desc,
                "category": cat,
                "example": example,
            }
        )
    return out


def detect(text, entity_types=None):
    """Scan `text` for PII entities. Returns a list of entity dicts, ordered
    by start offset, with cross-recognizer overlap already resolved.
    """
    _check_text(text)
    wanted = _resolve_entity_types(entity_types)

    raw_results = []
    for entity_type in wanted:
        recognizer = _RECOGNIZERS[entity_type]
        raw_results.extend(recognizer.analyze(text, [entity_type]))

    if not raw_results:
        return []

    # Reuse presidio-anonymizer's own tested conflict-resolution pass — via
    # the no-op "keep" operator — instead of hand-rolling overlap merging.
    anon_inputs = [
        AnonRecognizerResult(
            entity_type=r.entity_type, start=r.start, end=r.end, score=r.score
        )
        for r in raw_results
    ]
    resolved = _anon_engine.anonymize(
        text=text,
        analyzer_results=anon_inputs,
        operators={"DEFAULT": OperatorConfig("keep")},
    )

    entities = []
    for item in resolved.items:
        best_raw = _best_overlapping(raw_results, item.entity_type, item.start, item.end)
        entities.append(
            {
                "entity_type": item.entity_type,
                "start": item.start,
                "end": item.end,
                "text": item.text if item.text is not None else text[item.start : item.end],
                "score": best_raw.score if best_raw else 0.0,
                "recognizer_name": (
                    (best_raw.recognition_metadata or {}).get("recognizer_name", "")
                    if best_raw
                    else ""
                ),
            }
        )
    entities.sort(key=lambda e: (e["start"], e["end"]))
    return entities


def _best_overlapping(raw_results, entity_type, start, end):
    candidates = [
        r
        for r in raw_results
        if r.entity_type == entity_type and not (r.end <= start or r.start >= end)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.score)


def _to_anon_results(entities):
    if not entities:
        raise PiiError("entities must be non-empty")
    # Respect the caller's score exactly as given — including an explicit
    # 0.0 — since it decides which entity wins when two spans of different
    # types overlap (see PiiEntity.score docs). A silent fallback here would
    # invert a caller's intentional "deprioritize this one" score=0.0.
    return [
        AnonRecognizerResult(entity_type=e.entity_type, start=e.start, end=e.end, score=e.score)
        for e in entities
    ]


def redact(text, entities):
    """Replace every entity span with "<ENTITY_TYPE>". Returns (new_text, count)."""
    _check_text(text)
    anon_results = _to_anon_results(entities)
    result = _anon_engine.anonymize(
        text=text,
        analyzer_results=anon_results,
        operators={"DEFAULT": OperatorConfig("replace", {})},
    )
    return result.text, len(result.items)


def mask(text, entities, chars_to_mask, masking_char, from_end):
    _check_text(text)
    anon_results = _to_anon_results(entities)
    effective_masking_char = masking_char if masking_char else "*"
    if len(effective_masking_char) != 1:
        raise PiiError("masking_char must be exactly one character")
    # 0/unset means "mask the whole span" — a large sentinel achieves that
    # via the operator's own min(len(entity_text), chars_to_mask) clamp,
    # regardless of any individual entity's actual length.
    effective_chars = chars_to_mask if chars_to_mask and chars_to_mask > 0 else 1_000_000
    result = _anon_engine.anonymize(
        text=text,
        analyzer_results=anon_results,
        operators={
            "DEFAULT": OperatorConfig(
                "mask",
                {
                    "chars_to_mask": effective_chars,
                    "masking_char": effective_masking_char,
                    "from_end": bool(from_end),
                },
            )
        },
    )
    return result.text, len(result.items)


_VALID_HASH_ALGOS = ("sha256", "sha512")


def hash_text(text, entities, hash_algorithm, salt):
    _check_text(text)
    anon_results = _to_anon_results(entities)
    algo = hash_algorithm or "sha256"
    if algo not in _VALID_HASH_ALGOS:
        raise PiiError(f"hash_algorithm must be one of {_VALID_HASH_ALGOS}, got {algo!r}")
    params = {"hash_type": algo}
    if salt:
        salt_bytes = salt.encode("utf-8")
        if len(salt_bytes) < 16:
            raise PiiError("salt must be at least 16 bytes once UTF-8 encoded")
        params["salt"] = salt_bytes
    result = _anon_engine.anonymize(
        text=text,
        analyzer_results=anon_results,
        operators={"DEFAULT": OperatorConfig("hash", params)},
    )
    return result.text, len(result.items)


def encrypt(text, entities, encryption_key):
    _check_text(text)
    _check_key(encryption_key)
    anon_results = _to_anon_results(entities)
    result = _anon_engine.anonymize(
        text=text,
        analyzer_results=anon_results,
        operators={"DEFAULT": OperatorConfig("encrypt", {"key": encryption_key})},
    )
    encrypted_entities = [
        {
            "entity_type": item.entity_type,
            "start": item.start,
            "end": item.end,
            "text": item.text,
            "score": 1.0,
            "recognizer_name": "",
        }
        for item in result.items
    ]
    return result.text, encrypted_entities


def decrypt(encrypted_text, encrypted_entities, encryption_key):
    _check_text(encrypted_text, field_name="encrypted_text")
    _check_key(encryption_key)
    if not encrypted_entities:
        raise PiiError("encrypted_entities must be non-empty")
    op_results = [
        OperatorResult(start=e.start, end=e.end, entity_type=e.entity_type)
        for e in encrypted_entities
    ]
    result = _deanon_engine.deanonymize(
        text=encrypted_text,
        entities=op_results,
        operators={"DEFAULT": OperatorConfig("decrypt", {"key": encryption_key})},
    )
    return result.text


def _check_key(key):
    if not key:
        raise PiiError("encryption_key is required")
    key_bytes = key.encode("utf-8")
    if len(key_bytes) not in (16, 24, 32):
        raise PiiError(
            f"encryption_key must be 16, 24, or 32 bytes once UTF-8 encoded "
            f"(AES-128/192/256); got {len(key_bytes)} bytes"
        )


def replace(text, entities, replacements, default_replacement):
    _check_text(text)
    anon_results = _to_anon_results(entities)
    default_value = default_replacement if default_replacement else "[REDACTED]"
    operators = {
        "DEFAULT": OperatorConfig("replace", {"new_value": default_value}),
    }
    for entity_type, new_value in (replacements or {}).items():
        operators[entity_type] = OperatorConfig("replace", {"new_value": new_value})
    result = _anon_engine.anonymize(
        text=text, analyzer_results=anon_results, operators=operators
    )
    return result.text, len(result.items)


_VALID_OPERATORS = ("redact", "mask", "hash", "replace")


def anonymize(
    text,
    entity_types,
    operator,
    chars_to_mask,
    masking_char,
    from_end,
    hash_algorithm,
    salt,
    replacements,
    default_replacement,
):
    """DetectPii + the chosen operator, in one call."""
    op = operator or "redact"
    if op not in _VALID_OPERATORS:
        raise PiiError(
            f"operator must be one of {_VALID_OPERATORS} (encrypt/decrypt need "
            f"explicit key handling — use the dedicated EncryptText/DecryptText "
            f"nodes), got {op!r}"
        )
    found = detect(text, entity_types)
    if not found:
        return text, found

    class _E:
        __slots__ = ("entity_type", "start", "end", "text", "score", "recognizer_name")

        def __init__(self, d):
            for k, v in d.items():
                setattr(self, k, v)

    entity_objs = [_E(e) for e in found]

    if op == "redact":
        new_text, _ = redact(text, entity_objs)
    elif op == "mask":
        new_text, _ = mask(text, entity_objs, chars_to_mask, masking_char, from_end)
    elif op == "hash":
        new_text, _ = hash_text(text, entity_objs, hash_algorithm, salt)
    else:
        new_text, _ = replace(text, entity_objs, replacements, default_replacement)

    return new_text, found
