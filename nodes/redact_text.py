from gen.messages_pb2 import RedactTextRequest, RedactTextResponse
from gen.axiom_context import AxiomContext

from nodes import _pii


def redact_text(ax: AxiomContext, input: RedactTextRequest) -> RedactTextResponse:
    """Replace every given entity span in `text` with a generic per-type
    placeholder token, e.g. "My email is jane@example.com" ->
    "My email is <EMAIL_ADDRESS>". Irreversible — the original values are
    discarded, not recoverable. Pass entities from a prior DetectPii call (or
    your own spans in the same PiiEntity shape). Malformed input (missing
    text, an empty entities list, or an out-of-bounds span) returns a
    structured error rather than crashing.
    """
    try:
        redacted_text, count = _pii.redact(input.text, list(input.entities))
    except _pii.PiiError as e:
        return RedactTextResponse(error=str(e))
    except Exception as e:  # noqa: BLE001 — e.g. an out-of-bounds span
        return RedactTextResponse(error=f"invalid entities: {e}")

    return RedactTextResponse(redacted_text=redacted_text, items_redacted=count)
