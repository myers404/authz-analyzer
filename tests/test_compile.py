from itertools import product

import pytest
from hypothesis import given
from hypothesis import strategies as st

from authz_analyzer.compile import compile_expression
from authz_analyzer.expressions import (
    And,
    Atom,
    Constant,
    Equiv,
    Implies,
    Not,
    Or,
    Xor,
    evaluate,
)
from authz_analyzer.parser import parse


def _expressions():
    leaves = st.sampled_from(
        [Constant(False), Constant(True), Atom("a"), Atom("b"), Atom("c")]
    )
    return st.recursive(
        leaves,
        lambda children: st.one_of(
            children.map(Not),
            st.tuples(children, children).map(lambda args: And(args)),
            st.tuples(children, children).map(lambda args: Or(args)),
            st.tuples(children, children, children).map(lambda args: Xor(args)),
            st.tuples(children, children).map(lambda args: Implies(*args)),
            st.tuples(children, children).map(lambda args: Equiv(*args)),
        ),
        max_leaves=12,
    )


@given(_expressions())
def test_compiled_bdd_matches_direct_evaluation(expression) -> None:
    bdd, root = compile_expression(expression)

    for values in product((False, True), repeat=len(bdd.variables)):
        assignment = dict(zip(bdd.variables, values, strict=True))
        assert bdd.evaluate(root, assignment) is evaluate(expression, assignment)


def test_compiler_uses_first_occurrence_variable_order() -> None:
    bdd, _ = compile_expression(parse("z & a | z & m"))

    assert bdd.variables == ("z", "a", "m")


def test_compiler_accepts_an_explicit_variable_universe() -> None:
    bdd, root = compile_expression(Atom("a"), variable_order=("unused", "a"))

    assert bdd.variables == ("unused", "a")
    assert bdd.evaluate(root, {"unused": False, "a": True}) is True


def test_compiler_rejects_an_order_missing_a_referenced_atom() -> None:
    with pytest.raises(ValueError, match="missing"):
        compile_expression(And((Atom("a"), Atom("b"))), variable_order=("a",))


def test_parse_compile_and_evaluate_end_to_end() -> None:
    expression = parse('admin | (owner & !"account suspended")')
    assignment = {"admin": False, "owner": True, "account suspended": False}
    bdd, root = compile_expression(expression)

    assert evaluate(expression, assignment) is True
    assert bdd.evaluate(root, assignment) is True
