"""Unit tests that outlines simple usage of the Mysto FPE library (https://github.com/mysto/python-fpe)."""
import pytest
from ff3 import FF3Cipher

from tink_fpe import CharacterGroup


KEY = "00112233445566778899aabbccddeeff"
TWEAK = "0011223344556677"
# ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


@pytest.mark.parametrize("plaintext", [("Foobar"), ("abc123")])
def test_encrypt_decrypt(plaintext: str) -> None:
    alphabet = CharacterGroup.ALPHANUMERIC
    ff3 = FF3Cipher.withCustomAlphabet(key=KEY, tweak=TWEAK, alphabet=alphabet)
    ciphertext = ff3.encrypt_with_tweak(plaintext, TWEAK)
    assert len(ciphertext) == len(plaintext)
    assert all(c in alphabet for c in ciphertext)
