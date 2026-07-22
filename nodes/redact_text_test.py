from gen.messages_pb2 import PiiEntity, RedactTextRequest, RedactTextResponse
from nodes.redact_text import redact_text
from nodes.testkit import FakeAxiomContext


def _entity(text, needle, etype, score=0.6):
    start = text.index(needle)
    return PiiEntity(entity_type=etype, start=start, end=start + len(needle), text=needle, score=score)


def test_redact_replaces_span_with_type_placeholder():
    ax = FakeAxiomContext()
    text = "My email is jane@example.com, call me."
    entity = _entity(text, "jane@example.com", "EMAIL_ADDRESS")
    r = redact_text(ax, RedactTextRequest(text=text, entities=[entity]))
    assert isinstance(r, RedactTextResponse)
    assert not r.error
    assert r.redacted_text == "My email is <EMAIL_ADDRESS>, call me."
    assert r.items_redacted == 1


def test_redact_multiple_entities():
    ax = FakeAxiomContext()
    text = "Email a@b.com or call 555-1234."
    entities = [
        _entity(text, "a@b.com", "EMAIL_ADDRESS"),
        _entity(text, "555-1234", "PHONE_NUMBER", score=0.4),
    ]
    r = redact_text(ax, RedactTextRequest(text=text, entities=entities))
    assert not r.error
    assert r.redacted_text == "Email <EMAIL_ADDRESS> or call <PHONE_NUMBER>."
    assert r.items_redacted == 2


def test_redact_empty_entities_is_structured_error():
    ax = FakeAxiomContext()
    r = redact_text(ax, RedactTextRequest(text="hello", entities=[]))
    assert r.error


def test_redact_out_of_bounds_span_is_structured_error_not_crash():
    ax = FakeAxiomContext()
    entity = PiiEntity(entity_type="EMAIL_ADDRESS", start=0, end=999, text="x", score=0.5)
    r = redact_text(ax, RedactTextRequest(text="short", entities=[entity]))
    assert r.error


def test_explicit_zero_score_is_respected_not_silently_promoted():
    """Regression: a caller-supplied score=0.0 must NOT be treated as if it
    were the max score. Two different-type entities cover the SAME span; the
    one explicitly scored 0.0 must lose the overlap to the higher-scored one.
    """
    ax = FakeAxiomContext()
    text = "See example.com for details."
    span = "example.com"
    start = text.index(span)
    end = start + len(span)
    low = PiiEntity(entity_type="EMAIL_ADDRESS", start=start, end=end, text=span, score=0.0)
    high = PiiEntity(entity_type="URL", start=start, end=end, text=span, score=0.5)
    r = redact_text(ax, RedactTextRequest(text=text, entities=[low, high]))
    assert not r.error
    assert r.redacted_text == "See <URL> for details."
    assert "<EMAIL_ADDRESS>" not in r.redacted_text
