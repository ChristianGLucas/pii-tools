from gen.messages_pb2 import HashTextRequest, HashTextResponse
from gen.axiom_context import AxiomContext

from nodes import _pii


def hash_text(ax: AxiomContext, input: HashTextRequest) -> HashTextResponse:
    """Replace every given entity span with a one-way SHA-256/512 hash digest
    (hex-encoded) of its original value — irreversible pseudonymization. By
    default each entity gets a fresh random salt per call, so the SAME value
    hashes DIFFERENTLY every call (safer against dictionary attacks, but not
    linkable across calls); pass `salt` (at least 16 bytes once UTF-8
    encoded) for deterministic, linkable hashing instead. Pass entities from
    a prior DetectPii call. Malformed input (missing text, an empty entities
    list, an unsupported hash_algorithm, a too-short salt, or an
    out-of-bounds span) returns a structured error rather than crashing.
    """
    try:
        hashed_text, count = _pii.hash_text(
            input.text, list(input.entities), input.hash_algorithm, input.salt
        )
    except _pii.PiiError as e:
        return HashTextResponse(error=str(e))
    except Exception as e:  # noqa: BLE001 — e.g. an out-of-bounds span
        return HashTextResponse(error=f"invalid entities: {e}")

    return HashTextResponse(hashed_text=hashed_text, items_hashed=count)
