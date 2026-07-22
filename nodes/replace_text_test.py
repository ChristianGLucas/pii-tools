from gen.messages_pb2 import PiiEntity, ReplaceTextRequest, ReplaceTextResponse
from nodes.replace_text import replace_text
from nodes.testkit import FakeAxiomContext


def _entity(text, needle, etype, score=0.6):
    start = text.index(needle)
    return PiiEntity(entity_type=etype, start=start, end=start + len(needle), text=needle, score=score)


def test_replace_uses_per_type_mapping():
    ax = FakeAxiomContext()
    text = "Email a@b.com or call 555-1234."
    entities = [
        _entity(text, "a@b.com", "EMAIL_ADDRESS"),
        _entity(text, "555-1234", "PHONE_NUMBER", score=0.4),
    ]
    r = replace_text(
        ax,
        ReplaceTextRequest(
            text=text,
            entities=entities,
            replacements={"EMAIL_ADDRESS": "[email withheld]"},
        ),
    )
    assert isinstance(r, ReplaceTextResponse)
    assert not r.error
    assert r.replaced_text == "Email [email withheld] or call [REDACTED]."
    assert r.items_replaced == 2


def test_replace_default_replacement_override():
    ax = FakeAxiomContext()
    text = "Call 555-1234."
    entity = _entity(text, "555-1234", "PHONE_NUMBER", score=0.4)
    r = replace_text(
        ax,
        ReplaceTextRequest(text=text, entities=[entity], default_replacement="[hidden]"),
    )
    assert not r.error
    assert r.replaced_text == "Call [hidden]."


def test_replace_empty_entities_is_structured_error():
    ax = FakeAxiomContext()
    r = replace_text(ax, ReplaceTextRequest(text="hi", entities=[]))
    assert r.error
