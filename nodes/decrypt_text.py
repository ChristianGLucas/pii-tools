from gen.messages_pb2 import DecryptTextRequest, DecryptTextResponse
from gen.axiom_context import AxiomContext

from nodes import _pii


def decrypt_text(ax: AxiomContext, input: DecryptTextRequest) -> DecryptTextResponse:
    """Reverse a prior EncryptText call: recover the original plaintext for
    each encrypted span in `encrypted_text`, given the matching
    encrypted_entities (as returned by EncryptText) and the SAME
    encryption_key used to encrypt. A wrong key or corrupted ciphertext
    fails decryption cleanly. Malformed input (missing encrypted_text, empty
    encrypted_entities, a wrong-length key, an out-of-bounds span, or a
    key/ciphertext mismatch) returns a structured error rather than
    crashing.
    """
    try:
        decrypted_text = _pii.decrypt(
            input.encrypted_text, list(input.encrypted_entities), input.encryption_key
        )
    except _pii.PiiError as e:
        return DecryptTextResponse(error=str(e))
    except Exception as e:  # noqa: BLE001 — bad key, corrupted ciphertext, bad span
        return DecryptTextResponse(error=f"decryption failed: {e}")

    return DecryptTextResponse(decrypted_text=decrypted_text)
