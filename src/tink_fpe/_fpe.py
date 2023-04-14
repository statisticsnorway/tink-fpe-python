"""This module defines the interface for Format-Preserving Encryption (FPE)."""

import abc
from enum import Enum


class UnknownCharacterStrategy(Enum):
    """UnknownCharacterStrategy defines how encryption/decryption should handle non-alphabet characters.

    The underlying FPE algorithm restricts the type of plaintext characters that can be encrypted. Only characters
    defined in the defined alphabet can be used. Encountering non-alphabet characters can be handled in
    different ways.
    """

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


class CharacterGroup:
    """CharacterGroup holds different types of character groups, suitable for composing FPE alphabets."""

    ALPHANUMERIC = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    """Default alphanumeric characters: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"""

    """Numeric characters: 0123456789"""
    DIGITS = "0123456789"


class FpeParams:
    """FpeParams is used as an argument when invoking encrypt and decrypt functions.

    It conveys additional details such as how to handle unknown characters, using a custom tweak, etc.
    """

    def __init__(
        self,
        strategy: UnknownCharacterStrategy = UnknownCharacterStrategy.FAIL,
        tweak: bytes = b"",
        redaction_char: str = "",
        charset: str = "utf-8",
    ):
        self.unknown_character_strategy = strategy
        self.tweak = tweak
        self.redaction_char = redaction_char
        self.charset = charset


_DEFAULT_FPE_PARAMS = FpeParams()


class Fpe(metaclass=abc.ABCMeta):
    """Interface for Format-Preserving Encryption.

    FPE is a type of encryption family that allows for the encryption of data while preserving the original format
    and length of the plaintext. This is useful in scenarios where data must be encrypted, but the format of the data
    must remain unchanged for compatibility with existing systems or processes.
    """

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes, params: FpeParams = _DEFAULT_FPE_PARAMS) -> bytes:
        """Deterministically encrypt plaintext using Format-Preserving Encryption."""
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes, params: FpeParams = _DEFAULT_FPE_PARAMS) -> bytes:
        """Deterministically decrypt ciphertext using Format-Preserving Encryption."""
        raise NotImplementedError()
