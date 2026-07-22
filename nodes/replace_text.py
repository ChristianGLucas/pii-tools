from gen.messages_pb2 import ReplaceTextRequest, ReplaceTextResponse
from gen.axiom_context import AxiomContext

from nodes import _pii


def replace_text(ax: AxiomContext, input: ReplaceTextRequest) -> ReplaceTextResponse:
    """Replace every given entity span with a caller-supplied substitute
    value, e.g. swap every EMAIL_ADDRESS for "[email withheld]" via
    replacements while every other entity type falls back to
    default_replacement (defaults to "[REDACTED]"). Pass entities from a
    prior DetectPii call. Malformed input (missing text, an empty entities
    list, or an out-of-bounds span) returns a structured error rather than
    crashing.
    """
    try:
        replaced_text, count = _pii.replace(
            input.text,
            list(input.entities),
            dict(input.replacements),
            input.default_replacement,
        )
    except _pii.PiiError as e:
        return ReplaceTextResponse(error=str(e))
    except Exception as e:  # noqa: BLE001 — e.g. an out-of-bounds span
        return ReplaceTextResponse(error=f"invalid entities: {e}")

    return ReplaceTextResponse(replaced_text=replaced_text, items_replaced=count)
