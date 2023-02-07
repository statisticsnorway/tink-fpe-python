"""Format-Preserving Encryption wrapper."""

from typing import Type
from typing import cast

from tink import core

from tink_fpe import _fpe


class _WrappedFpe(_fpe.Fpe):
    """Implements FPE for a set of Fpe primitives."""

    def __init__(self, pset: core.PrimitiveSet):
        self._primitive_set = pset

    def encrypt(self, plaintext: bytes, params: _fpe.FpeParams = _fpe._DEFAULT_FPE_PARAMS) -> bytes:
        """Deterministically encrypt plaintext using Format-Preserving Encryption."""
        primary = self._primitive_set.primary()
        # return primary.identifier + primary.primitive.encrypt(plaintext, tweak)
        return cast(bytes, primary.primitive.encrypt(plaintext, params))

    def decrypt(self, ciphertext: bytes, params: _fpe.FpeParams = _fpe._DEFAULT_FPE_PARAMS) -> bytes:
        """Deterministically decrypt ciphertext using Format-Preserving Encryption."""
        # Let's try all RAW keys.
        for entry in self._primitive_set.raw_primitives():
            try:
                return cast(bytes, entry.primitive.decrypt(ciphertext, params))
            except core.TinkError:
                pass
        # nothing works.
        raise core.TinkError("Decryption failed.")


class FpeWrapper(core.PrimitiveWrapper[_fpe.Fpe, _fpe.Fpe]):  # type: ignore
    """FpeWrapper is a PrimitiveWrapper for Format-Preserving Encryption.

    The created primitive works with a keyset (rather than a single key). To
    encrypt a plaintext, it uses the primary key in the keyset. To decrypt, the primitive tries all
    keys with OutputPrefixType RAW.

    TODO: Look at DeterministicAead for inspiration on how to optimize this. Currently a keyset with
    multiple keys might suffer a performance penalty, depending on the number of keys in the keyset.
    We don't have the luxury of encoding key id stuff into the ciphertext - unless we do this in some other clever way.
    """

    def wrap(self, pset: core.PrimitiveSet) -> _fpe.Fpe:
        """Wrap a PrimitiveSet."""
        return _WrappedFpe(pset)

    def primitive_class(self) -> Type[_fpe.Fpe]:
        """Return the primitive type."""
        return _fpe.Fpe

    def input_primitive_class(self) -> Type[_fpe.Fpe]:
        """Return the primitive type."""
        return _fpe.Fpe
