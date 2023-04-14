"""Pre-generated KeyTemplate for FPE FFX DeterministicAead.

One can use these templates to generate a new tink_pb2.Keyset with
tink_pb2.KeysetHandle. To generate a new keyset that contains a single
fpe_ffx_pb2.FpeFfxKey, one can do:
handle = keyset_handle.KeysetHandle(fpe_key_templates.FPE_FF31_256_ALPHANUMERIC).
"""

from tink.proto import tink_pb2

from tink_fpe import _fpe_ffx_key_manager
from tink_fpe._fpe import CharacterGroup
from tink_fpe.proto.fpe_ffx_pb2 import FfxMode
from tink_fpe.proto.fpe_ffx_pb2 import FpeFfxKeyFormat


def _create_fpe_ffx_key_template(key_size: int, mode: FfxMode.ValueType, alphabet: str) -> tink_pb2.KeyTemplate:
    """Creates an FPE FFX KeyTemplate, and fills in its values."""
    fpe_ffx_key_format = FpeFfxKeyFormat()
    fpe_ffx_key_format.key_size = key_size
    fpe_ffx_key_format.params.mode = mode
    fpe_ffx_key_format.params.alphabet = alphabet

    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = _fpe_ffx_key_manager._FPE_FFX_KEY_TYPE_URL
    key_template.output_prefix_type = tink_pb2.RAW
    key_template.value = fpe_ffx_key_format.SerializeToString()
    return key_template


FPE_FF31_256_ALPHANUMERIC = _create_fpe_ffx_key_template(
    key_size=256, mode=FfxMode.FF31, alphabet=CharacterGroup.ALPHANUMERIC
)
FPE_FF31_192_ALPHANUMERIC = _create_fpe_ffx_key_template(
    key_size=192, mode=FfxMode.FF31, alphabet=CharacterGroup.ALPHANUMERIC
)
FPE_FF31_128_ALPHANUMERIC = _create_fpe_ffx_key_template(
    key_size=128, mode=FfxMode.FF31, alphabet=CharacterGroup.ALPHANUMERIC
)
FPE_FF31_256_DIGITS = _create_fpe_ffx_key_template(key_size=256, mode=FfxMode.FF31, alphabet=CharacterGroup.DIGITS)
FPE_FF31_192_DIGITS = _create_fpe_ffx_key_template(key_size=192, mode=FfxMode.FF31, alphabet=CharacterGroup.DIGITS)
FPE_FF31_128_DIGITS = _create_fpe_ffx_key_template(key_size=128, mode=FfxMode.FF31, alphabet=CharacterGroup.DIGITS)
