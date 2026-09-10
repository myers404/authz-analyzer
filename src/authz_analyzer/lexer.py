import json
from dataclasses import dataclass
from enum import StrEnum


class TokenKind(StrEnum):
    ATOM = "atom"
    TRUE = "true"
    FALSE = "false"
    NOT = "not"
    AND = "and"
    XOR = "xor"
    OR = "or"
    IMPLIES = "implies"
    EQUIV = "equiv"
    LEFT_PAREN = "("
    RIGHT_PAREN = ")"
    EOF = "end of input"


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    value: str
    start: int
    end: int


class ExpressionSyntaxError(ValueError):
    def __init__(
        self, message: str, source: str, start: int, end: int | None = None
    ) -> None:
        self.source = source
        self.start = start
        self.end = start if end is None else end
        super().__init__(f"{message} at offset {start}")


_WORDS = {
    "true": TokenKind.TRUE,
    "false": TokenKind.FALSE,
    "not": TokenKind.NOT,
    "and": TokenKind.AND,
    "xor": TokenKind.XOR,
    "or": TokenKind.OR,
    "implies": TokenKind.IMPLIES,
    "equiv": TokenKind.EQUIV,
}

_SYMBOLS = (
    ("<->", TokenKind.EQUIV),
    ("->", TokenKind.IMPLIES),
    ("!", TokenKind.NOT),
    ("&", TokenKind.AND),
    ("^", TokenKind.XOR),
    ("|", TokenKind.OR),
    ("(", TokenKind.LEFT_PAREN),
    (")", TokenKind.RIGHT_PAREN),
)


def _is_name_start(char: str) -> bool:
    return char == "_" or "A" <= char <= "Z" or "a" <= char <= "z"


def _is_name_char(char: str) -> bool:
    return _is_name_start(char) or "0" <= char <= "9" or char in "_.:/-"


def tokenize(source: str) -> tuple[Token, ...]:
    if not isinstance(source, str):
        raise TypeError("expression source must be a string")

    tokens: list[Token] = []
    position = 0
    while position < len(source):
        if source[position].isspace():
            position += 1
            continue

        start = position
        if source[position] == '"':
            try:
                value, length = json.JSONDecoder().raw_decode(source[position:])
            except json.JSONDecodeError as error:
                error_position = position + error.pos
                raise ExpressionSyntaxError(
                    "invalid quoted atom", source, error_position
                ) from None
            position += length
            tokens.append(Token(TokenKind.ATOM, value, start, position))
            continue

        symbol = next(
            (
                (text, kind)
                for text, kind in _SYMBOLS
                if source.startswith(text, position)
            ),
            None,
        )
        if symbol is not None:
            text, kind = symbol
            position += len(text)
            tokens.append(Token(kind, text, start, position))
            continue

        if _is_name_start(source[position]):
            position += 1
            while position < len(source) and _is_name_char(source[position]):
                if source.startswith("->", position):
                    break
                position += 1
            value = source[start:position]
            tokens.append(
                Token(_WORDS.get(value, TokenKind.ATOM), value, start, position)
            )
            continue

        raise ExpressionSyntaxError(
            f"unexpected character {source[position]!r}",
            source,
            position,
            position + 1,
        )

    tokens.append(Token(TokenKind.EOF, "", len(source), len(source)))
    return tuple(tokens)


__all__ = ["ExpressionSyntaxError", "Token", "TokenKind", "tokenize"]
