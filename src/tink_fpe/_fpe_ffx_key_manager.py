import secrets
from typing import Type

import tink
from tink.proto import tink_pb2

from tink_fpe import _fpe
from tink_fpe import _fpe_ff3
from tink_fpe import _fpe_wrapper
from tink_fpe.proto.fpe_ffx_pb2 import FpeFfxKey
from tink_fpe.proto.fpe_ffx_pb2 import FpeFfxKeyFormat


_FPE_FFX_KEY_TYPE_URL = "type.googleapis.com/ssb.crypto.tink.FpeFfxKey"


class FpeFfxKeyManager(tink.core.KeyManager[FpeFfxKey]):  # type: ignore
    """Tink key manager for FPE FFX keys."""

    def __init__(self) -> None:
        self._type_url = _FPE_FFX_KEY_TYPE_URL

    def primitive_class(self) -> Type[_fpe.Fpe]:
        """Return the primitive type."""
        return _fpe.Fpe

    def primitive(self, key_data: tink_pb2.KeyData) -> _fpe.Fpe:
        """Return the primitive."""
        fpe_ffx_key = FpeFfxKey()
        fpe_ffx_key.ParseFromString(key_data.value)
        return _fpe_ff3.FpeFf3(key=fpe_ffx_key.key_value, alphabet=fpe_ffx_key.params.alphabet)

    def key_type(self) -> str:
        """Return the key type."""
        return self._type_url

    def new_key_data(self, key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyData:
        """Create a new key."""
        ffx_key_format = FpeFfxKeyFormat()
        ffx_key_format.ParseFromString(key_template.value)
        ffx_key = FpeFfxKey()
        ffx_key.params.mode = ffx_key_format.params.mode
        ffx_key.params.alphabet = ffx_key_format.params.alphabet
        ffx_key.key_value = secrets.token_bytes(nbytes=int(ffx_key_format.key_size / 8))
        ffx_key.version = 0

        key_data = tink_pb2.KeyData()
        key_data.type_url = self._type_url
        key_data.key_material_type = tink_pb2.KeyData.SYMMETRIC
        key_data.value = ffx_key.SerializeToString()
        return key_data


def register() -> None:
    """Register the key manager with Tink."""
    key_manager = FpeFfxKeyManager()
    tink.core.Registry.register_key_manager(key_manager, new_key_allowed=True)
    fpe_wrapper = _fpe_wrapper.FpeWrapper()
    tink.core.Registry.register_primitive_wrapper(fpe_wrapper)
