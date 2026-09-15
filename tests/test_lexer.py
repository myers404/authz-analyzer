import pytest

from authz_analyzer.lexer import ExpressionSyntaxError, TokenKind, tokenize


def test_tokenize_reports_decoded_values_and_source_spans() -> None:
    tokens = tokenize('a -> "b c"')

    assert [(token.kind, token.value, token.start, token.end) for token in tokens] == [
        (TokenKind.ATOM, "a", 0, 1),
        (TokenKind.IMPLIES, "->", 2, 4),
        (TokenKind.ATOM, "b c", 5, 10),
        (TokenKind.EOF, "", 10, 10),
    ]


def test_tokenize_supports_symbolic_operators() -> None:
    tokens = tokenize("! & ^ | -> <-> ( )")

    assert [token.kind for token in tokens] == [
        TokenKind.NOT,
        TokenKind.AND,
        TokenKind.XOR,
        TokenKind.OR,
        TokenKind.IMPLIES,
        TokenKind.EQUIV,
        TokenKind.LEFT_PAREN,
        TokenKind.RIGHT_PAREN,
        TokenKind.EOF,
    ]


def test_only_boolean_constants_are_reserved_words() -> None:
    tokens = tokenize("not and xor or implies equiv true false")

    assert [(token.kind, token.value) for token in tokens[:-1]] == [
        (TokenKind.ATOM, "not"),
        (TokenKind.ATOM, "and"),
        (TokenKind.ATOM, "xor"),
        (TokenKind.ATOM, "or"),
        (TokenKind.ATOM, "implies"),
        (TokenKind.ATOM, "equiv"),
        (TokenKind.TRUE, "true"),
        (TokenKind.FALSE, "false"),
    ]


def test_arrow_does_not_become_part_of_an_atom() -> None:
    tokens = tokenize("alpha-beta->gamma")

    assert [(token.kind, token.value) for token in tokens[:-1]] == [
        (TokenKind.ATOM, "alpha-beta"),
        (TokenKind.IMPLIES, "->"),
        (TokenKind.ATOM, "gamma"),
    ]


def test_quoted_atom_uses_json_string_escaping() -> None:
    token = tokenize(r'"line\n\u03bb"')[0]

    assert token.kind is TokenKind.ATOM
    assert token.value == "line\nλ"


@pytest.mark.parametrize("source", ["@", "1abc", "a١", '""', '"unterminated'])
def test_invalid_input_has_a_source_position(source: str) -> None:
    with pytest.raises(ExpressionSyntaxError) as error:
        tokenize(source)

    assert error.value.start >= 0
    assert error.value.end >= error.value.start


def test_syntax_error_reports_line_and_column() -> None:
    with pytest.raises(ExpressionSyntaxError) as error:
        tokenize("a &\n@")

    assert (error.value.line, error.value.column) == (2, 1)
    assert error.value.code == "invalid_syntax"
