from gen.messages_pb2 import EncryptTextRequest, EncryptTextResponse, PiiEntity
from gen.axiom_context import AxiomContext

from nodes import _pii


def encrypt_text(ax: AxiomContext, input: EncryptTextRequest) -> EncryptTextResponse:
    """Replace every given entity span with a REVERSIBLE AES-CBC ciphertext
    (base64-encoded, random IV per value), so the original value can be
    recovered later with DecryptText and the same key — use this instead of
    HashText when the PII must be recoverable by an authorized caller
    downstream. encryption_key must be exactly 16, 24, or 32 bytes once
    UTF-8 encoded (AES-128/192/256); the caller owns key generation and
    storage, this node never persists it. Returns encrypted_entities — the
    ciphertext spans' positions in the OUTPUT text — pass those (and the
    same key) to DecryptText. Malformed input (missing text, an empty
    entities list, a wrong-length key, or an out-of-bounds span) returns a
    structured error rather than crashing.
    """
    try:
        encrypted_text, encrypted_entities = _pii.encrypt(
            input.text, list(input.entities), input.encryption_key
        )
    except _pii.PiiError as e:
        return EncryptTextResponse(error=str(e))
    except Exception as e:  # noqa: BLE001 — e.g. an out-of-bounds span
        return EncryptTextResponse(error=f"invalid entities: {e}")

    return EncryptTextResponse(
        encrypted_text=encrypted_text,
        encrypted_entities=[
            PiiEntity(
                entity_type=e["entity_type"],
                start=e["start"],
                end=e["end"],
                text=e["text"],
                score=e["score"],
                recognizer_name=e["recognizer_name"],
            )
            for e in encrypted_entities
        ],
        items_encrypted=len(encrypted_entities),
    )
