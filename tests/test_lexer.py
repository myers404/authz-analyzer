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


def test_tokenize_supports_symbolic_and_word_operators() -> None:
    tokens = tokenize("! not & and ^ xor | or -> implies <-> equiv ( )")

    assert [token.kind for token in tokens] == [
        TokenKind.NOT,
        TokenKind.NOT,
        TokenKind.AND,
        TokenKind.AND,
        TokenKind.XOR,
        TokenKind.XOR,
        TokenKind.OR,
        TokenKind.OR,
        TokenKind.IMPLIES,
        TokenKind.IMPLIES,
        TokenKind.EQUIV,
        TokenKind.EQUIV,
        TokenKind.LEFT_PAREN,
        TokenKind.RIGHT_PAREN,
        TokenKind.EOF,
    ]


def test_keywords_are_case_sensitive_and_require_a_whole_bare_name() -> None:
    tokens = tokenize("notable AND true false")

    assert [(token.kind, token.value) for token in tokens[:-1]] == [
        (TokenKind.ATOM, "notable"),
        (TokenKind.ATOM, "AND"),
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


@pytest.mark.parametrize("source", ["@", "1abc", "a١", '"unterminated'])
def test_invalid_input_has_a_source_position(source: str) -> None:
    with pytest.raises(ExpressionSyntaxError) as error:
        tokenize(source)

    assert error.value.start >= 0
    assert error.value.end >= error.value.start
