import typing as t

def redaction_char_of(alphabet: str) -> str:
    for c in "*?_-Xx0":
        if c in alphabet:
            return c
    raise ValueError(f"Unable to deduce redaction character for alphabet '{alphabet}")


def remove_unknown_chars(text: str, known_chars: str) -> str:
    return text.translate(str.maketrans("", "", "".join([c for c in set(text) if c not in known_chars])))


def has_unknown_chars(text: str, known_chars: str) -> bool:
    return not all(c in known_chars for c in text)


def redact_unknown_chars(text: str, known_chars: str, redaction_char: str) -> str:
    return ''.join([redaction_char if char not in known_chars else char for char in text])


class CharacterSkipper:
    def __init__(self, text: str, allowed_chars: str) -> None:
        self._skipped: t.List[t.Tuple[int, str]] = [(i, c) for i, c in enumerate(text) if c not in allowed_chars]
        self._processed_text: str = ''.join(c for c in text if c in allowed_chars)

    def get_processed_text(self) -> str:
        return self._processed_text

    def has_skipped(self) -> bool:
        return len(self._skipped) > 0

    def inject_skipped_into(self, text: str) -> str:
        for index, char in self._skipped:
            text = text[:index] + char + text[index:]
        return text
