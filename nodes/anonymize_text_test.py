from gen.messages_pb2 import AnonymizeTextRequest, AnonymizeTextResponse
from nodes.anonymize_text import anonymize_text
from nodes.testkit import FakeAxiomContext


def test_anonymize_default_operator_is_redact():
    ax = FakeAxiomContext()
    text = "My email is jane@example.com today."
    r = anonymize_text(ax, AnonymizeTextRequest(text=text, entity_types=["EMAIL_ADDRESS"]))
    assert isinstance(r, AnonymizeTextResponse)
    assert not r.error
    assert r.anonymized_text == "My email is <EMAIL_ADDRESS> today."
    assert len(r.entities) == 1
    assert r.entities[0].entity_type == "EMAIL_ADDRESS"
    # Entities are offsets into the ORIGINAL text, not the anonymized one.
    assert text[r.entities[0].start : r.entities[0].end] == "jane@example.com"


def test_anonymize_mask_operator():
    ax = FakeAxiomContext()
    card = "4111111111111111"
    text = f"Card {card} on file."
    r = anonymize_text(
        ax,
        AnonymizeTextRequest(
            text=text,
            entity_types=["CREDIT_CARD"],
            operator="mask",
            chars_to_mask=len(card) - 4,
            masking_char="*",
        ),
    )
    assert not r.error
    assert r.anonymized_text == "Card " + "*" * (len(card) - 4) + "1111 on file."


def test_anonymize_replace_operator():
    ax = FakeAxiomContext()
    text = "Email jane@example.com now."
    r = anonymize_text(
        ax,
        AnonymizeTextRequest(
            text=text,
            entity_types=["EMAIL_ADDRESS"],
            operator="replace",
            replacements={"EMAIL_ADDRESS": "[withheld]"},
        ),
    )
    assert not r.error
    assert r.anonymized_text == "Email [withheld] now."


def test_anonymize_no_entities_found_returns_text_unchanged():
    ax = FakeAxiomContext()
    text = "Nothing sensitive here."
    r = anonymize_text(ax, AnonymizeTextRequest(text=text, entity_types=["EMAIL_ADDRESS"]))
    assert not r.error
    assert r.anonymized_text == text
    assert list(r.entities) == []


def test_anonymize_unsupported_operator_is_structured_error():
    ax = FakeAxiomContext()
    r = anonymize_text(ax, AnonymizeTextRequest(text="jane@example.com", operator="encrypt"))
    assert r.error
