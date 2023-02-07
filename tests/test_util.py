"""Unit tests for the _util module."""
import pytest

from tink_fpe import _util


ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
DIGITS = "0123456789"


def test_redaction_char_of() -> None:
    with pytest.raises(ValueError):
        _util.redaction_char_of("")
        _util.redaction_char_of("123")

    assert _util.redaction_char_of(ALPHANUMERIC) == "X"
    assert _util.redaction_char_of(DIGITS) == "0"
