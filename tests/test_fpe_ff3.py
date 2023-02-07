import pytest

import tink

from tink import JsonKeysetReader
from tink import cleartext_keyset_handle

from typing import cast

import tink_fpe
from tink_fpe import Fpe, FpeParams, UnknownCharacterStrategy
import typing as t

@pytest.fixture(scope='class')
def register_tink_fpe() -> None:
    tink_fpe.register()


@pytest.fixture(scope='class')
def static_keysets() -> t.Dict[str, str]:
    return {
        'FPE_FF31_256_ALPHANUMERIC': '{"primaryKeyId":1720617146,"key":[{"keyData":{"typeUrl":"type.googleapis.com/ssb.crypto.tink.FpeFfxKey","value":"EiBoBeUFkoew7YJObcgcz1uOmzdhJFkPP7driAxAuS0UiRpCEAIaPkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1720617146,"outputPrefixType":"RAW"}]}',
        'FPE_FF31_192_ALPHANUMERIC': '{"primaryKeyId":1928982491,"key":[{"keyData":{"typeUrl":"type.googleapis.com/ssb.crypto.tink.FpeFfxKey","value":"EhizrnA3ckTddEhK3xWtrTMe6MEGpDFGXIUaQhACGj5BQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1928982491,"outputPrefixType":"RAW"}]}',
        'FPE_FF31_128_ALPHANUMERIC': '{"primaryKeyId":1382079328,"key":[{"keyData":{"typeUrl":"type.googleapis.com/ssb.crypto.tink.FpeFfxKey","value":"EhD4978shQNRpBNaBjbF4KO4GkIQAho+QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1382079328,"outputPrefixType":"RAW"}]}'
    }


@pytest.fixture(scope='class')
def ff31_256_alphanumeric(register_tink_fpe: None, static_keysets: t.Dict[str, str]) -> Fpe:
    keyset_handle = cleartext_keyset_handle.read(JsonKeysetReader(static_keysets['FPE_FF31_256_ALPHANUMERIC']))
    return cast(Fpe, keyset_handle.primitive(Fpe))


@pytest.fixture(scope='class')
def ff31_192_alphanumeric(register_tink_fpe: None, static_keysets: t.Dict[str, str]) -> Fpe:
    keyset_handle = cleartext_keyset_handle.read(JsonKeysetReader(static_keysets['FPE_FF31_192_ALPHANUMERIC']))
    return cast(Fpe, keyset_handle.primitive(Fpe))


@pytest.fixture(scope='class')
def ff31_128_alphanumeric(register_tink_fpe: None, static_keysets: t.Dict[str, str]) -> Fpe:
    keyset_handle = cleartext_keyset_handle.read(JsonKeysetReader(static_keysets['FPE_FF31_128_ALPHANUMERIC']))
    return cast(Fpe, keyset_handle.primitive(Fpe))


@pytest.mark.parametrize(
    "plaintext, expected_ciphertext",
    [
        ("Foobar", "6jZemW"),
        ("Foo bar", "6jZ emW"),
        ("If I could gather all the stars and hold them in my hand", "Tw 8 Vqp9k FVfYSv DqJ eSe 5nL68 BA8 SkV8 vhX4 Dc SP XImS"),
        ("A", "A"),
        ("123", "123"),
        ("abcd", "QCeY"),
        ("ab cd", "QC eY"),
        ("abc#", "abc#"),
        ("012345678901234567890123456789AB", "ULxO2Z2FeOfIpESyrRCBIj2bABCu4sAB"),
        ("012345678901234567890123456789#", "ULxO2Z2FeOfIpESyrRCBIj2bABCu4s#")
    ]
)
def test_ff31_encrypt_decrypt_alphanumeric_with_skip(ff31_256_alphanumeric: Fpe, plaintext: str, expected_ciphertext: str) -> None:
    fpe = ff31_256_alphanumeric
    params = FpeParams(strategy=UnknownCharacterStrategy.SKIP)
    ciphertext = fpe.encrypt(plaintext.encode('utf-8'), params)
    assert ciphertext == expected_ciphertext.encode('utf-8')
    decrypted = fpe.decrypt(ciphertext, params)
    assert decrypted.decode('utf-8') == plaintext


@pytest.mark.parametrize(
    "plaintext, expected_ciphertext, expected_plaintext",
    [
        ("Foobar", "6jZemW", "Foobar"),
        ("Foo bar", "qFejvAC", "FooXbar"),
        ("If I could gather all the stars and hold them in my hand", "qslVtH0Zu2Gcy3I89NeWRwGShILxssNPGM7LABI8wxLcY23UGevd2NaV", "IfXIXcouldXgatherXallXtheXstarsXandXholdXthemXinXmyXhand"),
        ("A", "A", "A"),
        ("123", "123", "123"),
        ("abcd", "QCeY", "abcd"),
        ("ab cd", "KtxVK", "abXcd"),
        ("abc#", "SuU6", "abcX"),
        ("012345678901234567890123456789AB", "ULxO2Z2FeOfIpESyrRCBIj2bABCu4sAB", "012345678901234567890123456789AB"),
        ("012345678901234567890123456789#", "ULxO2Z2FeOfIpESyrRCBIj2bABCu4sX", "012345678901234567890123456789X")
    ]
)
def test_ff31_encrypt_decrypt_alphanumeric_with_redact(ff31_256_alphanumeric: Fpe, plaintext: str, expected_ciphertext: str, expected_plaintext: str) -> None:
    fpe = ff31_256_alphanumeric
    params = FpeParams(strategy=UnknownCharacterStrategy.REDACT)
    ciphertext = fpe.encrypt(plaintext.encode('utf-8'), params)
    assert ciphertext == expected_ciphertext.encode('utf-8')
    decrypted = fpe.decrypt(ciphertext, params)
    assert decrypted.decode('utf-8') == expected_plaintext


@pytest.mark.parametrize(
    "plaintext, expected_ciphertext, expected_plaintext",
    [
        ("Foobar", "6jZemW", "Foobar"),
        ("Foo bar", "6jZemW", "Foobar"),
        ("If I could gather all the stars and hold them in my hand", "Tw8Vqp9kFVfYSvDqJeSe5nL68BA8SkV8vhX4DcSPXImS", "IfIcouldgatherallthestarsandholdtheminmyhand"),
        ("A", "A", "A"),
        ("123", "123", "123"),
        ("abcd", "QCeY", "abcd"),
        ("ab cd", "QCeY", "abcd"),
        ("abc#", "abc", "abc"),
        ("012345678901234567890123456789AB", "ULxO2Z2FeOfIpESyrRCBIj2bABCu4sAB", "012345678901234567890123456789AB"),
        ("012345678901234567890123456789#", "ULxO2Z2FeOfIpESyrRCBIj2bABCu4s", "012345678901234567890123456789")
    ]
)
def test_ff31_encrypt_decrypt_alphanumeric_with_delete(ff31_256_alphanumeric: Fpe, plaintext: str, expected_ciphertext: str, expected_plaintext: str) -> None:
    fpe = ff31_256_alphanumeric
    params = FpeParams(strategy=UnknownCharacterStrategy.DELETE)
    ciphertext = fpe.encrypt(plaintext.encode('utf-8'), params)
    assert ciphertext == expected_ciphertext.encode('utf-8')
    decrypted = fpe.decrypt(ciphertext, params)
    assert decrypted.decode('utf-8') == expected_plaintext


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
        ("012345678901234567890123456789#", False)
    ]
)
def test_ff31_encrypt_decrypt_alphanumeric_with_fail(ff31_256_alphanumeric: Fpe, plaintext: str, is_ok: bool) -> None:
    fpe = ff31_256_alphanumeric
    params = FpeParams(strategy=UnknownCharacterStrategy.FAIL)
    if (is_ok):
        ciphertext = fpe.encrypt(plaintext.encode('utf-8'), params)
        decrypted = fpe.decrypt(ciphertext, params)
    else:
        with pytest.raises(ValueError):
            fpe.encrypt(plaintext.encode('utf-8'), params)


def test_create_new_key_material(register_tink_fpe: None) -> None:
    for key_template in (tink_fpe.fpe_key_templates.FPE_FF31_256_ALPHANUMERIC,
                         tink_fpe.fpe_key_templates.FPE_FF31_192_ALPHANUMERIC,
                         tink_fpe.fpe_key_templates.FPE_FF31_128_ALPHANUMERIC):
        tink.new_keyset_handle(key_template)
