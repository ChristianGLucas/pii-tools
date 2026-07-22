from gen.messages_pb2 import PiiEntity, DecryptTextRequest, DecryptTextResponse
from nodes.decrypt_text import decrypt_text
from nodes.testkit import FakeAxiomContext

KEY_16 = "0123456789abcdef"


def test_decrypt_empty_entities_is_structured_error():
    ax = FakeAxiomContext()
    r = decrypt_text(ax, DecryptTextRequest(encrypted_text="anything", encrypted_entities=[], encryption_key=KEY_16))
    assert isinstance(r, DecryptTextResponse)
    assert r.error


def test_decrypt_wrong_length_key_is_structured_error():
    ax = FakeAxiomContext()
    entity = PiiEntity(entity_type="US_SSN", start=0, end=8, text="ignored", score=1.0)
    r = decrypt_text(
        ax,
        DecryptTextRequest(encrypted_text="Zm9vYmFy", encrypted_entities=[entity], encryption_key="short"),
    )
    assert r.error


def test_decrypt_corrupted_ciphertext_is_structured_error_not_crash():
    ax = FakeAxiomContext()
    entity = PiiEntity(entity_type="US_SSN", start=0, end=8, text="ignored", score=1.0)
    r = decrypt_text(
        ax,
        DecryptTextRequest(
            encrypted_text="not-valid-base64-ciphertext!!",
            encrypted_entities=[entity],
            encryption_key=KEY_16,
        ),
    )
    assert r.error
