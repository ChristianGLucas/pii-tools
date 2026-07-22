from gen.messages_pb2 import MaskTextRequest, MaskTextResponse
from gen.axiom_context import AxiomContext

from nodes import _pii


def mask_text(ax: AxiomContext, input: MaskTextRequest) -> MaskTextResponse:
    """Partially obscure every given entity span in place, revealing only a
    caller-chosen number of characters — e.g. mask a 16-digit card number
    down to "************1111" (chars_to_mask=12, from_end=false) so the
    text stays useful for display while hiding the sensitive value. Pass
    entities from a prior DetectPii call. chars_to_mask=0 (the default) masks
    the entire span. Malformed input (missing text, an empty entities list, a
    masking_char that isn't exactly one character, or an out-of-bounds span)
    returns a structured error rather than crashing.
    """
    try:
        masked_text, count = _pii.mask(
            input.text,
            list(input.entities),
            input.chars_to_mask,
            input.masking_char,
            input.from_end,
        )
    except _pii.PiiError as e:
        return MaskTextResponse(error=str(e))
    except Exception as e:  # noqa: BLE001 — e.g. an out-of-bounds span
        return MaskTextResponse(error=f"invalid entities: {e}")

    return MaskTextResponse(masked_text=masked_text, items_masked=count)
