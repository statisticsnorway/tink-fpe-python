"""This module contains misc utility methods used by the FPE primitive implementations."""
import typing as t


def redaction_char_of(alphabet: str) -> str:
    """Deduce redaction character (a character that can be used for substitution) from an alphabet."""
    for c in "*?_-Xx0":
        if c in alphabet:
            return c
    raise ValueError(f"Unable to deduce redaction character for alphabet '{alphabet}")


def remove_unknown_chars(text: str, known_chars: str) -> str:
    """Remove characters from a string that are not present in another string.

    :param text: the string to remove characters from
    :param known_chars: string representing a set of characters to retain
    :return: text without "unknown" characters
    """
    return text.translate(str.maketrans("", "", "".join([c for c in set(text) if c not in known_chars])))


def has_unknown_chars(text: str, known_chars: str) -> bool:
    """Check if a string contains characters not present in another string.

    :param text: the string to check
    :param known_chars: string representing a set of "known" characters
    :return: True if a string contains characters not present in another string, else False
    """
    return not all(c in known_chars for c in text)


def redact_unknown_chars(text: str, known_chars: str, redaction_char: str) -> str:
    """Redact characters from a string that are not present in another string.

    :param text: the string to redact unknown characters from
    :param known_chars: string representing a set of characters to retain
    :param redaction_char: character to substitute "unknown" characters with
    :return: redacted text
    """
    return "".join([redaction_char if char not in known_chars else char for char in text])


class CharacterSkipper:
    """CharacterSkipper is used for removing "non-allowed" characters from a string.

    It keeps track of removed/skipped characters including their original indexes, and provides a function for
    injecting these characters at their respective indexes.
    """

    def __init__(self, text: str, allowed_chars: str) -> None:
        self._skipped: t.List[t.Tuple[int, str]] = [(i, c) for i, c in enumerate(text) if c not in allowed_chars]
        self._processed_text: str = "".join(c for c in text if c in allowed_chars)

    def get_processed_text(self) -> str:
        """Return the text with "non-allowed" characters removed."""
        return self._processed_text

    def has_skipped(self) -> bool:
        """Return True if the CharacterSkipper has removed any characters."""
        return len(self._skipped) > 0

    def inject_skipped_into(self, text: str) -> str:
        """Inject skipped characters at their respective indexes into a string.

        :param text: the string to be injected with skipped characters
        :return: a string injected with skipped characters
        """
        for index, char in self._skipped:
            text = text[:index] + char + text[index:]
        return text
