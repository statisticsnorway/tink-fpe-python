import typing as t
from typing import cast

import pytest
from tink import JsonKeysetReader
from tink import read_keyset_handle
from tink.integration import gcpkms

import tink_fpe
from tink_fpe import Fpe
from tink_fpe import FpeParams
from tink_fpe import UnknownCharacterStrategy


kek_uri = "gcp-kms://projects/dev-sirius/locations/europe-north1/keyRings/pseudo-service-common-keyring/cryptoKeys/pseudo-service-common-kek-1"
gcp_credentials = "../private/gcp/sa-keys/dev-dapla-pseudo-service-test-sa-key.json"


@pytest.fixture(scope="class")
def register_tink_fpe() -> None:
    tink_fpe.register()


@pytest.fixture(scope="class")
def static_keysets() -> t.Dict[str, str]:
    return {
        "WRAPPED_FPE_FF31_256_ALPHANUMERIC": '{"encryptedKeyset":"CiQAp91NBsClBYjw4AS9sOdB65peMwlzY4AiOzyMe+b+dFjSBuIS2QEAZ30rtRcDkuvtUgeENQCt29Vsalf+FtaNZc8wpOXKb3sD2c8hTXKaf34iq2QRMaQUBXxG+YSJPV4PvJZMGydZpjowM9K2eAJFZs5JaVxb3BMfUt0miNaORZmczqZhKlXXHbMoQ71GLwfSnf4jJnIRJK4s38ThnxS2ebm4b5T0qno6PWg84TtUw9eIIieqlUFhIqBjCcMugGTsE+xfWIOct22RDEUI3cAboCew5ppjOREAxzbaH8LaUBct5eLN8wtakY3Vv8KxBoT3Hq6fnNSSGOKmkqMVrK0p","keysetInfo":{"primaryKeyId":593699223,"keyInfo":[{"typeUrl":"type.googleapis.com/ssb.crypto.tink.FpeFfxKey","status":"ENABLED","keyId":593699223,"outputPrefixType":"RAW"}]}}'
    }


@pytest.fixture(scope="class")
def ff31_256_alphanumeric(register_tink_fpe: None, static_keysets: t.Dict[str, str]) -> Fpe:
    gcp_client = gcpkms.GcpKmsClient(kek_uri, gcp_credentials)
    kms_aead = gcp_client.get_aead(kek_uri)
    reader = JsonKeysetReader(serialized_keyset=static_keysets["WRAPPED_FPE_FF31_256_ALPHANUMERIC"])
    keyset_handle = read_keyset_handle(keyset_reader=reader, master_key_aead=kms_aead)
    return cast(Fpe, keyset_handle.primitive(Fpe))


@pytest.mark.parametrize(
    "plaintext, expected_ciphertext",
    [
        ("Foobar", "6jZemW"),
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


