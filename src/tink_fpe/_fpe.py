"""This module defines the interface for Format-Preserving Encryption (FPE)."""

import abc
from enum import Enum

class UnknownCharacterStrategy(Enum):
    FAIL = 1
    """Raise an error and bail out if encountering a non-alphabet character."""

    SKIP = 2
    """Ignore non-alphabet characters, leaving them unencrypted (nested into the ciphertext)."""

    REDACT = 3
    """ Before processing the plaintext, replace any characters that are not part of the alphabet with an
    alphabet-compliant character. Warning: Using this strategy means that decryption may not result in the exact
    same plaintext being restored."""

    DELETE = 4
    """ Remove all characters that are not part of the alphabet prior to processing. Warning: Using this strategy
    implies that the length of the plaintext and ciphertext may differ. Furthermore, decryption may not result in the
    exact same plaintext being restored."""



class FpeParams:
    def __init__(self,
                 strategy: UnknownCharacterStrategy = UnknownCharacterStrategy.FAIL,
                 tweak: bytes = b'',
                 redaction_char: str = ''):
        self.unknown_character_strategy = strategy
        self.tweak = tweak
        self.redaction_char = redaction_char

_DEFAULT_FPE_PARAMS = FpeParams()

class Fpe(metaclass=abc.ABCMeta):
    """Interface for Format-Preserving Encryption.
    """

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes, params: FpeParams = _DEFAULT_FPE_PARAMS) -> bytes:
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes, params: FpeParams = _DEFAULT_FPE_PARAMS) -> bytes:
        raise NotImplementedError()

