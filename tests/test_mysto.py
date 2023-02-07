from ff3 import FF3Cipher
import pytest

KEY = "00112233445566778899aabbccddeeff"
TWEAK = "0011223344556677"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


@pytest.mark.parametrize(
    "plaintext",
    [
        ("Foobar"),
        ("abc123")
    ]
)
def test_encrypt_decrypt(plaintext: str) -> None:
    ff3 = FF3Cipher.withCustomAlphabet(key=KEY, tweak=TWEAK, alphabet=ALPHABET)
    ciphertext = ff3.encrypt_with_tweak(plaintext, TWEAK)
    assert len(ciphertext) == len(plaintext)
    assert all(c in ALPHABET for c in ciphertext)
