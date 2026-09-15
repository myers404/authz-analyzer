import pytest
from hypothesis import given
from hypothesis import strategies as st

from authz_analyzer.expressions import (
    And,
    Atom,
    Constant,
    Equiv,
    Implies,
    Not,
    Or,
    Xor,
)
from authz_analyzer.lexer import ExpressionSyntaxError
from authz_analyzer.parser import parse


def _parenthesized_expressions():
    leaves = st.sampled_from(
        [
            ("true", Constant(True)),
            ("false", Constant(False)),
            ("a", Atom("a")),
            ('"has space"', Atom("has space")),
        ]
    )
    return st.recursive(
        leaves,
        lambda children: st.one_of(
            children.map(lambda item: (f"!({item[0]})", Not(item[1]))),
            st.tuples(children, children).map(
                lambda items: (
                    f"({items[0][0]} & {items[1][0]})",
                    And((items[0][1], items[1][1])),
                )
            ),
            st.tuples(children, children).map(
                lambda items: (
                    f"({items[0][0]} | {items[1][0]})",
                    Or((items[0][1], items[1][1])),
                )
            ),
            st.tuples(children, children).map(
                lambda items: (
                    f"({items[0][0]} ^ {items[1][0]})",
                    Xor((items[0][1], items[1][1])),
                )
            ),
            st.tuples(children, children).map(
                lambda items: (
                    f"({items[0][0]} -> {items[1][0]})",
                    Implies(items[0][1], items[1][1]),
                )
            ),
            st.tuples(children, children).map(
                lambda items: (
                    f"({items[0][0]} <-> {items[1][0]})",
                    Equiv(items[0][1], items[1][1]),
                )
            ),
        ),
        max_leaves=12,
    )


@given(_parenthesized_expressions())
def test_parse_generated_fully_parenthesized_expression(case) -> None:
    source, expected = case

    assert parse(source) == expected


def test_parse_operator_precedence() -> None:
    assert parse("!a & b ^ c | d -> e <-> f") == Equiv(
        Implies(
            Or((Xor((And((Not(Atom("a")), Atom("b"))), Atom("c"))), Atom("d"))),
            Atom("e"),
        ),
        Atom("f"),
    )


def test_implication_is_right_associative() -> None:
    assert parse("a -> b -> c") == Implies(Atom("a"), Implies(Atom("b"), Atom("c")))


def test_repeated_nary_operators_form_one_node() -> None:
    assert parse("a & b & c") == And((Atom("a"), Atom("b"), Atom("c")))
    assert parse("a | b | c") == Or((Atom("a"), Atom("b"), Atom("c")))
    assert parse("a ^ b ^ c") == Xor((Atom("a"), Atom("b"), Atom("c")))


def test_parentheses_override_precedence() -> None:
    assert parse("(a | b) & c") == And((Or((Atom("a"), Atom("b"))), Atom("c")))


def test_parse_constants_and_quoted_atoms() -> None:
    assert parse('true & false | "true" | "has space"') == Or(
        (
            And((Constant(True), Constant(False))),
            Atom("true"),
            Atom("has space"),
        )
    )


@pytest.mark.parametrize(
    "source",
    ["", '""', "()", "a b", "a &", "& a", "(a", "a)", "a <->"],
)
def test_parse_rejects_incomplete_or_trailing_input(source: str) -> None:
    with pytest.raises(ExpressionSyntaxError) as error:
        parse(source)

    assert error.value.start <= len(source)
