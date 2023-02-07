from ff3 import FF3Cipher

from tink_fpe import _util


# TODO: Use imports from tink_fpe instead of _fpe.<class>

from tink_fpe import _fpe

# TODO: Define constants properly
# TODO: Describe the weakness for long texts that prevent the last characters from being encrypted

_NULL_HEX_TWEAK = "00000000000000"

_MIN_CHUNK_SIZE = 4
_MAX_CHUNK_SIZE = 30

def _hex_tweak_of(b: bytes) -> str:
    return _NULL_HEX_TWEAK if b is None or len(b) == 0 else b.hex()


class FpeFf3(_fpe.Fpe):

    def __init__(self, key: bytes, alphabet: str):
        self._alphabet = alphabet
        self._default_redaction_char = _util.redaction_char_of(alphabet)
        self._ff3 = FF3Cipher.withCustomAlphabet(key=key.hex(), tweak=_NULL_HEX_TWEAK, alphabet=alphabet)

    def encrypt(self, plaintext: bytes, params: _fpe.FpeParams) -> bytes:
        pt: str = plaintext.decode('utf-8')
        tweak: str = _hex_tweak_of(params.tweak)
        char_skipper = None

        if params.unknown_character_strategy == _fpe.UnknownCharacterStrategy.FAIL:
            if _util.has_unknown_chars(text=pt, known_chars=self._alphabet):
                raise ValueError(f"Plaintext can only contain characters from the alphabet '{self._alphabet}'")
        elif params.unknown_character_strategy == _fpe.UnknownCharacterStrategy.SKIP:
            char_skipper = _util.CharacterSkipper(pt, self._alphabet)
            pt = char_skipper.get_processed_text()
        elif params.unknown_character_strategy == _fpe.UnknownCharacterStrategy.DELETE:
            pt = _util.remove_unknown_chars(text=pt, known_chars=self._alphabet)
        elif params.unknown_character_strategy == _fpe.UnknownCharacterStrategy.REDACT:
            pt = _util.redact_unknown_chars(text=pt, known_chars=self._alphabet, redaction_char=params.redaction_char or self._default_redaction_char)

        ct = []
        for pos in range(0, len(pt), _MAX_CHUNK_SIZE):
            chunk = pt[pos:min(pos + _MAX_CHUNK_SIZE, len(pt))]
            if len(chunk) < _MIN_CHUNK_SIZE:
                ct.append(chunk)
            else:
                ct.append(self._ff3.encrypt_with_tweak(plaintext=chunk, tweak=tweak))
        ciphertext = ''.join(ct)

        if char_skipper and char_skipper.has_skipped():
            ciphertext = char_skipper.inject_skipped_into(ciphertext)

        return ciphertext.encode('utf-8')



    def decrypt(self, ciphertext: bytes, params: _fpe.FpeParams) -> bytes:
        ct: str = ciphertext.decode('utf-8')
        tweak: str = _hex_tweak_of(params.tweak)
        char_skipper = None

        if params.unknown_character_strategy == _fpe.UnknownCharacterStrategy.SKIP:
            char_skipper = _util.CharacterSkipper(ct, self._alphabet)
            ct = char_skipper.get_processed_text()

        pt = []
        for pos in range(0, len(ct), _MAX_CHUNK_SIZE):
            chunk = ct[pos:min(pos + _MAX_CHUNK_SIZE, len(ct))]
            if len(chunk) < _MIN_CHUNK_SIZE:
                pt.append(chunk)
            else:
                pt.append(self._ff3.decrypt_with_tweak(ciphertext=chunk, tweak=tweak))
        plaintext = ''.join(pt)

        if char_skipper and char_skipper.has_skipped():
            plaintext = char_skipper.inject_skipped_into(plaintext)

        return plaintext.encode('utf-8')

