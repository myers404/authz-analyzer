from itertools import product

import pytest
from hypothesis import given
from hypothesis import strategies as st

from authz_analyzer.bdd import BDDNodeLimitError
from authz_analyzer.compile import compile_expression, compile_expressions
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


def test_compiler_appends_atoms_missing_from_an_explicit_partial_order() -> None:
    bdd, _ = compile_expression(
        And((Atom("z"), Atom("a"), Atom("m"))), variable_order=("m",)
    )

    assert bdd.variables == ("m", "a", "z")


def test_compile_multiple_expressions_into_one_variable_universe() -> None:
    expressions = (parse("z & a"), parse("a -> m"), Not(Atom("z")))
    bdd, roots = compile_expressions(expressions)

    assert bdd.variables == ("z", "a", "m")
    assert len(roots) == len(expressions)
    for values in product((False, True), repeat=len(bdd.variables)):
        assignment = dict(zip(bdd.variables, values, strict=True))
        assert tuple(bdd.evaluate(root, assignment) for root in roots) == tuple(
            evaluate(expression, assignment) for expression in expressions
        )


def test_compile_multiple_accepts_an_iterable_and_preserves_root_order() -> None:
    expressions = (Atom(name) for name in ("b", "a"))
    bdd, roots = compile_expressions(expressions)

    assert bdd.variables == ("b", "a")
    assert bdd.evaluate(roots[0], {"b": True, "a": False}) is True
    assert bdd.evaluate(roots[1], {"b": True, "a": False}) is False


def test_compile_no_expressions_returns_an_empty_manager() -> None:
    bdd, roots = compile_expressions(())

    assert bdd.variables == ()
    assert roots == ()


def test_shared_partial_order_appends_atoms_from_every_expression() -> None:
    bdd, _ = compile_expressions(
        (Atom("z"), Atom("a"), Atom("b")), variable_order=("b",)
    )

    assert bdd.variables == ("b", "a", "z")


def test_parse_compile_and_evaluate_end_to_end() -> None:
    expression = parse('admin | (owner & !"account suspended")')
    assignment = {"admin": False, "owner": True, "account suspended": False}
    bdd, root = compile_expression(expression)

    assert evaluate(expression, assignment) is True
    assert bdd.evaluate(root, assignment) is True


def test_compiler_passes_the_node_limit_to_the_manager() -> None:
    with pytest.raises(BDDNodeLimitError):
        compile_expression(And((Atom("a"), Atom("b"))), max_nodes=1)
