"""Unit tests for the _fpe_ff3 module."""
import typing as t
from typing import cast

import pytest
import tink
from tink import JsonKeysetReader
from tink import cleartext_keyset_handle

import tink_fpe
from tink_fpe import Fpe
from tink_fpe import FpeParams
from tink_fpe import UnknownCharacterStrategy


@pytest.fixture(scope="class")
def register_tink_fpe() -> None:
    tink_fpe.register()


@pytest.fixture(scope="class")
def static_keysets() -> t.Dict[str, str]:
    return {
        "FPE_FF31_256_ALPHANUMERIC": '{"primaryKeyId":832997605,"key":[{"keyData":{"typeUrl":"type.googleapis.com/ssb.crypto.tink.FpeFfxKey","value":"EiCCNkK81HHmUY4IjEzXDrGLOT5t+7PGQ1eIyrGqGa4S3BpCEAIaPjAxMjM0NTY3ODlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":832997605,"outputPrefixType":"RAW"}]}',
        "FPE_FF31_192_ALPHANUMERIC": '{"primaryKeyId":1472396213,"key":[{"keyData":{"typeUrl":"type.googleapis.com/ssb.crypto.tink.FpeFfxKey","value":"EhjK5UIa3TqJKbcdrnLeGt/9qppevXZJgQ8aQhACGj4wMTIzNDU2Nzg5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1472396213,"outputPrefixType":"RAW"}]}',
        "FPE_FF31_128_ALPHANUMERIC": '{"primaryKeyId":1285197635,"key":[{"keyData":{"typeUrl":"type.googleapis.com/ssb.crypto.tink.FpeFfxKey","value":"EhBiuZBtjIqW+UdSRoGclarMGkIQAho+MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1285197635,"outputPrefixType":"RAW"}]}',
    }


@pytest.fixture(scope="class")
def ff31_256_alphanumeric(register_tink_fpe: None, static_keysets: t.Dict[str, str]) -> Fpe:
    keyset_handle = cleartext_keyset_handle.read(JsonKeysetReader(static_keysets["FPE_FF31_256_ALPHANUMERIC"]))
    return cast(Fpe, keyset_handle.primitive(Fpe))


@pytest.fixture(scope="class")
def ff31_192_alphanumeric(register_tink_fpe: None, static_keysets: t.Dict[str, str]) -> Fpe:
    keyset_handle = cleartext_keyset_handle.read(JsonKeysetReader(static_keysets["FPE_FF31_192_ALPHANUMERIC"]))
    return cast(Fpe, keyset_handle.primitive(Fpe))


@pytest.fixture(scope="class")
def ff31_128_alphanumeric(register_tink_fpe: None, static_keysets: t.Dict[str, str]) -> Fpe:
    keyset_handle = cleartext_keyset_handle.read(JsonKeysetReader(static_keysets["FPE_FF31_128_ALPHANUMERIC"]))
    return cast(Fpe, keyset_handle.primitive(Fpe))


@pytest.mark.parametrize(
    "plaintext, expected_ciphertext",
    [
        ("Foobar", "b7kOqd"),
        ("Foo bar", "b7k Oqd"),
        (
            "If I could gather all the stars and hold them in my hand",
            "sr D Gm8se ic4Wid mTd Scz FpVR9 gdn 5dcW 5PCh xD 6C 9GFk",
        ),
        ("A", "A"),
        ("123", "123"),
        ("abcd", "NcFL"),
        ("ab cd", "Nc FL"),
        ("abc#", "abc#"),
        ("012345678901234567890123456789AB", "3wOIPgonKck22IVcL19ti42uFmKM8mAB"),
        ("012345678901234567890123456789#", "3wOIPgonKck22IVcL19ti42uFmKM8m#"),
    ],
)
def test_ff31_encrypt_decrypt_alphanumeric_with_skip(
    ff31_256_alphanumeric: Fpe, plaintext: str, expected_ciphertext: str
) -> None:
    fpe = ff31_256_alphanumeric
    params = FpeParams(strategy=UnknownCharacterStrategy.SKIP)
    ciphertext = fpe.encrypt(plaintext.encode("utf-8"), params)
    assert ciphertext == expected_ciphertext.encode("utf-8")
    decrypted = fpe.decrypt(ciphertext, params)
    assert decrypted.decode("utf-8") == plaintext


@pytest.mark.parametrize(
    "plaintext, expected_ciphertext, expected_plaintext",
    [
        ("Foobar", "b7kOqd", "Foobar"),
        ("Foo bar", "EXoaFHU", "FooXbar"),
        (
            "If I could gather all the stars and hold them in my hand",
            "t75QqfsrW4ilmkoZzDnBpeyj2il6445WMw63II8UB8kBD5PQESgVng7e",
            "IfXIXcouldXgatherXallXtheXstarsXandXholdXthemXinXmyXhand",
        ),
        ("A", "A", "A"),
        ("123", "123", "123"),
        ("abcd", "NcFL", "abcd"),
        ("ab cd", "kADJO", "abXcd"),
        ("abc#", "tHSF", "abcX"),
        ("012345678901234567890123456789AB", "3wOIPgonKck22IVcL19ti42uFmKM8mAB", "012345678901234567890123456789AB"),
        ("012345678901234567890123456789#", "3wOIPgonKck22IVcL19ti42uFmKM8mX", "012345678901234567890123456789X"),
    ],
)
def test_ff31_encrypt_decrypt_alphanumeric_with_redact(
    ff31_256_alphanumeric: Fpe, plaintext: str, expected_ciphertext: str, expected_plaintext: str
) -> None:
    fpe = ff31_256_alphanumeric
    params = FpeParams(strategy=UnknownCharacterStrategy.REDACT)
    ciphertext = fpe.encrypt(plaintext.encode("utf-8"), params)
    assert ciphertext == expected_ciphertext.encode("utf-8")
    decrypted = fpe.decrypt(ciphertext, params)
    assert decrypted.decode("utf-8") == expected_plaintext


@pytest.mark.parametrize(
    "plaintext, expected_ciphertext, expected_plaintext",
    [
        ("Foobar", "b7kOqd", "Foobar"),
        ("Foo bar", "b7kOqd", "Foobar"),
        (
            "If I could gather all the stars and hold them in my hand",
            "srDGm8seic4WidmTdSczFpVR9gdn5dcW5PChxD6C9GFk",
            "IfIcouldgatherallthestarsandholdtheminmyhand",
        ),
        ("A", "A", "A"),
        ("123", "123", "123"),
        ("abcd", "NcFL", "abcd"),
        ("ab cd", "NcFL", "abcd"),
        ("abc#", "abc", "abc"),
        ("012345678901234567890123456789AB", "3wOIPgonKck22IVcL19ti42uFmKM8mAB", "012345678901234567890123456789AB"),
        ("012345678901234567890123456789#", "3wOIPgonKck22IVcL19ti42uFmKM8m", "012345678901234567890123456789"),
    ],
)
def test_ff31_encrypt_decrypt_alphanumeric_with_delete(
    ff31_256_alphanumeric: Fpe, plaintext: str, expected_ciphertext: str, expected_plaintext: str
) -> None:
    fpe = ff31_256_alphanumeric
    params = FpeParams(strategy=UnknownCharacterStrategy.DELETE)
    ciphertext = fpe.encrypt(plaintext.encode("utf-8"), params)
    assert ciphertext == expected_ciphertext.encode("utf-8")
    decrypted = fpe.decrypt(ciphertext, params)
    assert decrypted.decode("utf-8") == expected_plaintext


@pytest.mark.parametrize(
    "plaintext, is_ok",
    [
        ("Foobar", True),
        ("Foo bar", False),
        ("If I could gather all the stars and hold them in my hand", False),
        ("A", True),
        ("123", True),
        ("abcd", True),
        ("ab cd", False),
        ("abc#", False),
        ("012345678901234567890123456789AB", True),
        ("012345678901234567890123456789#", False),
    ],
)
def test_ff31_encrypt_decrypt_alphanumeric_with_fail(ff31_256_alphanumeric: Fpe, plaintext: str, is_ok: bool) -> None:
    fpe = ff31_256_alphanumeric
    params = FpeParams(strategy=UnknownCharacterStrategy.FAIL)
    if is_ok:
        ciphertext = fpe.encrypt(plaintext.encode("utf-8"), params)
        fpe.decrypt(ciphertext, params)
    else:
        with pytest.raises(ValueError):
            fpe.encrypt(plaintext.encode("utf-8"), params)


def test_create_new_key_material(register_tink_fpe: None) -> None:
    for key_template in (
        tink_fpe.fpe_key_templates.FPE_FF31_256_ALPHANUMERIC,
        tink_fpe.fpe_key_templates.FPE_FF31_192_ALPHANUMERIC,
        tink_fpe.fpe_key_templates.FPE_FF31_128_ALPHANUMERIC,
    ):
        tink.new_keyset_handle(key_template)
