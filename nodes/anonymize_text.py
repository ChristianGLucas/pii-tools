from gen.messages_pb2 import AnonymizeTextRequest, AnonymizeTextResponse, PiiEntity
from gen.axiom_context import AxiomContext

from nodes import _pii


def anonymize_text(ax: AxiomContext, input: AnonymizeTextRequest) -> AnonymizeTextResponse:
    """Convenience one-call op: detect PII in `text`, then immediately apply
    a single chosen anonymization operator to every entity found — equivalent
    to DetectPii followed by the matching operator node (RedactText/
    MaskText/HashText/ReplaceText), without a round trip. operator defaults
    to "redact"; use "mask", "hash", or "replace" for the others ("encrypt"/
    "decrypt" need explicit key handling — use the dedicated EncryptText/
    DecryptText nodes for those). Use the standalone Detect + operator nodes
    instead when you need to inspect or filter entities before anonymizing.
    Malformed input (missing text, text over the length limit, an
    unrecognized entity_types value, or an unsupported operator) returns a
    structured error rather than crashing.
    """
    try:
        anonymized_text, entities = _pii.anonymize(
            input.text,
            list(input.entity_types),
            input.operator,
            input.chars_to_mask,
            input.masking_char,
            input.from_end,
            input.hash_algorithm,
            input.salt,
            dict(input.replacements),
            input.default_replacement,
        )
    except _pii.PiiError as e:
        return AnonymizeTextResponse(error=str(e))
    except Exception as e:  # noqa: BLE001 — never crash on malformed input
        return AnonymizeTextResponse(error=f"anonymize failed: {e}")

    return AnonymizeTextResponse(
        anonymized_text=anonymized_text,
        entities=[
            PiiEntity(
                entity_type=e["entity_type"],
                start=e["start"],
                end=e["end"],
                text=e["text"],
                score=e["score"],
                recognizer_name=e["recognizer_name"],
            )
            for e in entities
        ],
    )
