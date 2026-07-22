from gen.messages_pb2 import PiiEntity, MaskTextRequest, MaskTextResponse
from nodes.mask_text import mask_text
from nodes.testkit import FakeAxiomContext


def _card_entity(text, start=5):
    return PiiEntity(entity_type="CREDIT_CARD", start=start, end=start + len(text), text=text, score=1.0)


def test_mask_reveals_last_4_digits():
    ax = FakeAxiomContext()
    card = "4111111111111111"
    text = f"Card {card} on file."
    entity = _card_entity(card)
    r = mask_text(
        ax,
        MaskTextRequest(text=text, entities=[entity], chars_to_mask=len(card) - 4, masking_char="*", from_end=False),
    )
    assert isinstance(r, MaskTextResponse)
    assert not r.error
    assert r.masked_text == "Card ************1111 on file."
    assert r.items_masked == 1


def test_mask_default_chars_to_mask_zero_masks_entire_span():
    ax = FakeAxiomContext()
    card = "4111111111111111"
    entity = _card_entity(card)
    r = mask_text(ax, MaskTextRequest(text=f"Card {card}.", entities=[entity]))
    assert not r.error
    assert r.masked_text == "Card " + "*" * len(card) + "."


def test_mask_from_end_true_masks_leading_characters():
    ax = FakeAxiomContext()
    card = "4111111111111111"
    entity = _card_entity(card)
    r = mask_text(
        ax,
        MaskTextRequest(text=f"Card {card}.", entities=[entity], chars_to_mask=4, masking_char="#", from_end=True),
    )
    assert not r.error
    assert r.masked_text == "Card " + card[:-4] + "####."


def test_mask_char_must_be_single_character():
    ax = FakeAxiomContext()
    entity = _card_entity("4111111111111111")
    r = mask_text(
        ax,
        MaskTextRequest(text="Card 4111111111111111.", entities=[entity], masking_char="**"),
    )
    assert r.error
