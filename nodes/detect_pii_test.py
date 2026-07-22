from gen.messages_pb2 import DetectPiiRequest, DetectPiiResponse
from nodes.detect_pii import detect_pii
from nodes.testkit import FakeAxiomContext


def _luhn_valid(number: str) -> bool:
    """Independent, from-scratch Luhn check — not the implementation under
    test (that's vendor/presidio_patterns' CreditCardRecognizer). Used to
    verify the recognizer's checksum decision against a hand-written oracle.
    """
    digits = [int(d) for d in number]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def test_multi_entity_text_finds_expected_spans():
    ax = FakeAxiomContext()
    text = "Contact Jane at jane.doe@example.com or +1 415-555-2671. Card 4111111111111111."
    r = detect_pii(ax, DetectPiiRequest(text=text))
    assert isinstance(r, DetectPiiResponse)
    assert not r.error
    assert r.text == text  # echoed, so a flow can chain straight into RedactText etc.

    by_type = {e.entity_type: e for e in r.entities}
    assert "EMAIL_ADDRESS" in by_type
    email = by_type["EMAIL_ADDRESS"]
    assert email.text == "jane.doe@example.com"
    assert text[email.start : email.end] == "jane.doe@example.com"

    assert "PHONE_NUMBER" in by_type
    assert by_type["PHONE_NUMBER"].text == "+1 415-555-2671"

    assert "CREDIT_CARD" in by_type
    card = by_type["CREDIT_CARD"]
    assert card.text == "4111111111111111"
    # Independent oracle: a passing Luhn check is why this scored 1.0.
    assert _luhn_valid(card.text)
    assert card.score == 1.0


def test_luhn_fail_scores_zero_and_is_dropped():
    ax = FakeAxiomContext()
    # One digit off from a valid Visa test number -> fails Luhn.
    bad_card = "4111111111111112"
    assert not _luhn_valid(bad_card)
    r = detect_pii(ax, DetectPiiRequest(text=f"Card {bad_card} please", entity_types=["CREDIT_CARD"]))
    assert not r.error
    assert list(r.entities) == []


def test_entity_types_filter_restricts_results():
    ax = FakeAxiomContext()
    text = "Email jane@example.com, phone +1 415-555-2671."
    r = detect_pii(ax, DetectPiiRequest(text=text, entity_types=["EMAIL_ADDRESS"]))
    assert not r.error
    types_found = {e.entity_type for e in r.entities}
    assert types_found == {"EMAIL_ADDRESS"}


def test_email_overlap_suppresses_nested_url_match():
    ax = FakeAxiomContext()
    # The URL recognizer alone matches "example.com" inside this address;
    # cross-type overlap resolution must keep only the higher-scored EMAIL_ADDRESS.
    text = "jane.doe@example.com"
    r = detect_pii(ax, DetectPiiRequest(text=text, entity_types=["EMAIL_ADDRESS", "URL"]))
    assert not r.error
    assert len(r.entities) == 1
    assert r.entities[0].entity_type == "EMAIL_ADDRESS"
    assert r.entities[0].start == 0
    assert r.entities[0].end == len(text)


def test_empty_text_returns_no_entities_no_error():
    ax = FakeAxiomContext()
    r = detect_pii(ax, DetectPiiRequest(text=""))
    assert not r.error
    assert list(r.entities) == []


def test_unknown_entity_type_is_structured_error():
    ax = FakeAxiomContext()
    r = detect_pii(ax, DetectPiiRequest(text="hello", entity_types=["NOT_A_REAL_TYPE"]))
    assert r.error
    assert "NOT_A_REAL_TYPE" in r.error


def test_oversized_text_is_structured_error_not_crash():
    ax = FakeAxiomContext()
    huge = "a" * 200_001
    r = detect_pii(ax, DetectPiiRequest(text=huge))
    assert r.error
    assert "200,000" in r.error or "200000" in r.error
