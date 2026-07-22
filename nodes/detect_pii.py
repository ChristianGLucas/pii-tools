from gen.messages_pb2 import DetectPiiRequest, DetectPiiResponse, PiiEntity
from gen.axiom_context import AxiomContext

from nodes import _pii


def detect_pii(ax: AxiomContext, input: DetectPiiRequest) -> DetectPiiResponse:
    """Scan free text for personally identifiable information: emails, phone
    numbers, credit card numbers, crypto wallet addresses, IBANs, IP/MAC
    addresses, URLs, dates, and several US-specific identifiers (SSN, ITIN,
    passport, driver's license, bank account, ABA routing number, medical
    license, NPI, MBI). Restrict to specific types with entity_types (see
    ListSupportedEntities), or leave empty to scan for everything supported.
    Returns each match's type, offsets into the input text, matched text,
    confidence score, and which recognizer found it. Overlapping matches of
    the same type are merged; overlapping matches of different types keep
    only the higher-scored one. Malformed input (missing text, text over the
    200,000-char limit, or an unrecognized entity_types value) returns a
    structured error rather than crashing. Does not detect free-text person
    names, locations, or organizations — those require an NLP/NER model,
    which this package deliberately does not bundle (see the README).
    """
    try:
        entities = _pii.detect(input.text, list(input.entity_types))
    except _pii.PiiError as e:
        return DetectPiiResponse(error=str(e))

    return DetectPiiResponse(
        text=input.text,
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
        ]
    )
