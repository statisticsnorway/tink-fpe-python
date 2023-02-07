"""Tink FPE Python."""

from tink_fpe import _fpe
from tink_fpe import _fpe_ffx_key_manager
from tink_fpe import _fpe_key_templates


Fpe = _fpe.Fpe
FpeParams = _fpe.FpeParams
UnknownCharacterStrategy = _fpe.UnknownCharacterStrategy
CharacterGroup = _fpe.CharacterGroup

fpe_key_templates = _fpe_key_templates
register = _fpe_ffx_key_manager.register
