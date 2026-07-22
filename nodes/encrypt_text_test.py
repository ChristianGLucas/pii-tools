from gen.messages_pb2 import PiiEntity, EncryptTextRequest, EncryptTextResponse
from nodes.encrypt_text import encrypt_text
from nodes.decrypt_text import decrypt_text
from gen.messages_pb2 import DecryptTextRequest
from nodes.testkit import FakeAxiomContext

KEY_16 = "0123456789abcdef"  # AES-128, exactly 16 bytes


def _entity(etype, text, start=6):
    return PiiEntity(entity_type=etype, start=start, end=start + len(text), text=text, score=0.6)


def test_encrypt_produces_different_ciphertext_than_plaintext():
    ax = FakeAxiomContext()
    ssn = "219-09-1234"
    text = f"SSN is {ssn}."
    entity = _entity("US_SSN", ssn, start=7)
    r = encrypt_text(ax, EncryptTextRequest(text=text, entities=[entity], encryption_key=KEY_16))
    assert isinstance(r, EncryptTextResponse)
    assert not r.error
    assert ssn not in r.encrypted_text
    assert r.items_encrypted == 1
    assert len(r.encrypted_entities) == 1
    assert r.encrypted_entities[0].entity_type == "US_SSN"


def test_encrypt_then_decrypt_round_trips_to_original():
    ax = FakeAxiomContext()
    ssn = "219-09-1234"
    text = f"SSN is {ssn}."
    entity = _entity("US_SSN", ssn, start=7)
    enc = encrypt_text(ax, EncryptTextRequest(text=text, entities=[entity], encryption_key=KEY_16))
    assert not enc.error

    dec = decrypt_text(
        ax,
        DecryptTextRequest(
            encrypted_text=enc.encrypted_text,
            encrypted_entities=list(enc.encrypted_entities),
            encryption_key=KEY_16,
        ),
    )
    assert not dec.error
    assert dec.decrypted_text == text


def test_decrypt_with_wrong_key_fails_cleanly():
    ax = FakeAxiomContext()
    ssn = "219-09-1234"
    text = f"SSN is {ssn}."
    entity = _entity("US_SSN", ssn, start=7)
    enc = encrypt_text(ax, EncryptTextRequest(text=text, entities=[entity], encryption_key=KEY_16))
    assert not enc.error

    wrong_key = "fedcba9876543210"  # different, still 16 bytes
    dec = decrypt_text(
        ax,
        DecryptTextRequest(
            encrypted_text=enc.encrypted_text,
            encrypted_entities=list(enc.encrypted_entities),
            encryption_key=wrong_key,
        ),
    )
    assert dec.error


def test_encrypt_rejects_wrong_length_key():
    ax = FakeAxiomContext()
    entity = _entity("US_SSN", "219-09-1234", start=7)
    r = encrypt_text(
        ax,
        EncryptTextRequest(text="SSN is 219-09-1234.", entities=[entity], encryption_key="tooshort"),
    )
    assert r.error


def test_encrypt_empty_entities_is_structured_error():
    ax = FakeAxiomContext()
    r = encrypt_text(ax, EncryptTextRequest(text="hello", entities=[], encryption_key=KEY_16))
    assert r.error
