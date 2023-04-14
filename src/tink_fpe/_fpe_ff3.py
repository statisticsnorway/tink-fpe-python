"""This module provides an implementation of FF3-1 mode of Format-Preserving Encryption (FPE)."""

from ff3 import FF3Cipher

from tink_fpe import _util
from tink_fpe._fpe import _DEFAULT_FPE_PARAMS
from tink_fpe._fpe import Fpe
from tink_fpe._fpe import FpeParams
from tink_fpe._fpe import UnknownCharacterStrategy


# TODO: Describe the weakness for long texts that prevent the last characters from being encrypted

_NULL_HEX_TWEAK = "00000000000000"
""" NULL_HEX_TWEAK is hexadecimal string representation of the default tweak. It is used if a tweak is not explicitly
specified by the user.

The tweak is a value used as an additional input to the encryption process. A tweak ensures that the same plaintext
and key will encrypt to different ciphertexts.</p>

The size of the tweak is usually recommended to be 128 bits (16 characters string) to provide sufficient randomness
and security. However, the underlying FF3-1 implementation (Mysto FPE (python)) enforces either 56 or 64 bits tweak
lengths (a 7 or 8 characters string). Thus, for compatibility reasons, this is also enforced here.
"""

_MIN_CHUNK_SIZE = 4
"""MIN_CHUNK_SIZE is the min number of characters for each plaintext fragment being encrypted.

The underlying FF3-1 implementation has limitations for minimum plaintext length. If the supplied plaintext is
shorter than a certain length (MIN_CHUNK_SIZE), the plaintext cannot be encrypted.
"""

_MAX_CHUNK_SIZE = 30
""" MAX_CHUNK_SIZE is the max number of characters for each plaintext fragment being encrypted.

The underlying FF3-1 implementation has limitations for maximum plaintext length (depending on alphabet radix).
If the supplied plaintext exceeds a certain length (MAX_CHUNK_SIZE), it is divided into chunks before being processed.

For more information, refer to: https://github.com/mysto/java-fpe#usage
"""


def _hex_tweak_of(b: bytes) -> str:
    """Return either the default 'null tweak" (if empty) or the hex representation of the provided bytes."""
    return _NULL_HEX_TWEAK if b is None or len(b) == 0 else b.hex()


class FpeFf3(Fpe):
    """Fpe primitive for the FF3-1 mode of Format-Preserving Encryption.

    The actual implementation of "chunk-wise encryption/decryption is delegated to the Mysto FPE library.
    """

    def __init__(self, key: bytes, alphabet: str):
        self._alphabet = alphabet
        self._default_redaction_char = _util.redaction_char_of(alphabet)
        self._ff3 = FF3Cipher.withCustomAlphabet(key=key.hex(), tweak=_NULL_HEX_TWEAK, alphabet=alphabet)

    def encrypt(self, plaintext: bytes, params: FpeParams = _DEFAULT_FPE_PARAMS) -> bytes:
        """Deterministically encrypt plaintext using FF3-1 mode.

        :param plaintext: plaintext to encrypt
        :param params: options that adjust how encryption will be performed
        :return: resulting ciphertext
        """
        pt: str = plaintext.decode(params.charset)
        tweak: str = _hex_tweak_of(params.tweak)
        char_skipper = None

        if params.unknown_character_strategy == UnknownCharacterStrategy.FAIL:
            if _util.has_unknown_chars(text=pt, known_chars=self._alphabet):
                raise ValueError(f"Plaintext can only contain characters from the alphabet {self._alphabet}")
        elif params.unknown_character_strategy == UnknownCharacterStrategy.SKIP:
            char_skipper = _util.CharacterSkipper(pt, self._alphabet)
            pt = char_skipper.get_processed_text()
        elif params.unknown_character_strategy == UnknownCharacterStrategy.DELETE:
            pt = _util.remove_unknown_chars(text=pt, known_chars=self._alphabet)
        elif params.unknown_character_strategy == UnknownCharacterStrategy.REDACT:
            pt = _util.redact_unknown_chars(
                text=pt,
                known_chars=self._alphabet,
                redaction_char=params.redaction_char or self._default_redaction_char,
            )

        ct = []
        for pos in range(0, len(pt), _MAX_CHUNK_SIZE):
            chunk = pt[pos : min(pos + _MAX_CHUNK_SIZE, len(pt))]
            if len(chunk) < _MIN_CHUNK_SIZE:
                ct.append(chunk)
            else:
                ct.append(self._ff3.encrypt_with_tweak(plaintext=chunk, tweak=tweak))
        ciphertext = "".join(ct)

        if char_skipper and char_skipper.has_skipped():
            ciphertext = char_skipper.inject_skipped_into(ciphertext)

        return ciphertext.encode(params.charset)

    def decrypt(self, ciphertext: bytes, params: FpeParams = _DEFAULT_FPE_PARAMS) -> bytes:
        """Deterministically decrypt ciphertext using FF3-1 mode.

        :param ciphertext: ciphertext to decrypt
        :param params: options that adjust how decryption will be performed. This should usually be the same as the
                       params used to encrypt.
        :return: resulting plaintext
        """
        ct: str = ciphertext.decode(params.charset)
        tweak: str = _hex_tweak_of(params.tweak)
        char_skipper = None

        if params.unknown_character_strategy == UnknownCharacterStrategy.SKIP:
            char_skipper = _util.CharacterSkipper(ct, self._alphabet)
            ct = char_skipper.get_processed_text()

        pt = []
        for pos in range(0, len(ct), _MAX_CHUNK_SIZE):
            chunk = ct[pos : min(pos + _MAX_CHUNK_SIZE, len(ct))]
            if len(chunk) < _MIN_CHUNK_SIZE:
                pt.append(chunk)
            else:
                pt.append(self._ff3.decrypt_with_tweak(ciphertext=chunk, tweak=tweak))
        plaintext = "".join(pt)

        if char_skipper and char_skipper.has_skipped():
            plaintext = char_skipper.inject_skipped_into(plaintext)

        return plaintext.encode(params.charset)
