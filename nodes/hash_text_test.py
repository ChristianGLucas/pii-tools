import hashlib

from gen.messages_pb2 import PiiEntity, HashTextRequest, HashTextResponse
from nodes.hash_text import hash_text
from nodes.testkit import FakeAxiomContext


def _entity(etype, text, start=6):
    return PiiEntity(entity_type=etype, start=start, end=start + len(text), text=text, score=0.6)


def test_hash_with_explicit_salt_matches_independent_sha256_computation():
    ax = FakeAxiomContext()
    email = "a@b.com"
    salt = "0123456789abcdef"  # 16 bytes
    text = f"Email {email}."
    entity = _entity("EMAIL_ADDRESS", email)
    r = hash_text(ax, HashTextRequest(text=text, entities=[entity], salt=salt))
    assert isinstance(r, HashTextResponse)
    assert not r.error

    # Independent oracle: reproduce the documented algorithm (text + salt,
    # sha256, hex) from scratch with stdlib hashlib, not by re-invoking the
    # implementation's own code path.
    expected_digest = hashlib.sha256(email.encode() + salt.encode()).hexdigest()
    assert r.hashed_text == f"Email {expected_digest}."
    assert r.items_hashed == 1


def test_hash_same_text_and_salt_is_deterministic():
    ax = FakeAxiomContext()
    entity = _entity("EMAIL_ADDRESS", "a@b.com")
    text = "Email a@b.com."
    r1 = hash_text(ax, HashTextRequest(text=text, entities=[entity], salt="0123456789abcdef"))
    r2 = hash_text(ax, HashTextRequest(text=text, entities=[entity], salt="0123456789abcdef"))
    assert not r1.error and not r2.error
    assert r1.hashed_text == r2.hashed_text


def test_hash_without_salt_is_non_deterministic_across_calls():
    ax = FakeAxiomContext()
    entity = _entity("EMAIL_ADDRESS", "a@b.com")
    text = "Email a@b.com."
    r1 = hash_text(ax, HashTextRequest(text=text, entities=[entity]))
    r2 = hash_text(ax, HashTextRequest(text=text, entities=[entity]))
    assert not r1.error and not r2.error
    # Documented behavior: a fresh random salt per call when none is supplied.
    assert r1.hashed_text != r2.hashed_text


def test_hash_salt_too_short_is_structured_error():
    ax = FakeAxiomContext()
    entity = _entity("EMAIL_ADDRESS", "a@b.com")
    r = hash_text(ax, HashTextRequest(text="Email a@b.com.", entities=[entity], salt="short"))
    assert r.error


def test_hash_unsupported_algorithm_is_structured_error():
    ax = FakeAxiomContext()
    entity = _entity("EMAIL_ADDRESS", "a@b.com")
    r = hash_text(ax, HashTextRequest(text="Email a@b.com.", entities=[entity], hash_algorithm="md5"))
    assert r.error
