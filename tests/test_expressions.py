from dataclasses import FrozenInstanceError

import pytest

from authz_analyzer.expressions import (
    And,
    Atom,
    Constant,
    Equiv,
    Implies,
    Not,
    Or,
    Xor,
    all_of,
    any_of,
    evaluate,
)


def test_expression_nodes_are_immutable_and_structurally_equal() -> None:
    expression = And((Atom("a"), Not(Atom("b"))))

    assert expression == And((Atom("a"), Not(Atom("b"))))
    assert hash(expression) == hash(And((Atom("a"), Not(Atom("b")))))
    with pytest.raises(FrozenInstanceError):
        expression.args = ()  # type: ignore[misc]


@pytest.mark.parametrize(
    ("expression", "assignment", "expected"),
    [
        (Constant(True), {}, True),
        (Constant(False), {}, False),
        (Atom("a"), {"a": True}, True),
        (Not(Atom("a")), {"a": True}, False),
        (And(()), {}, True),
        (And((Atom("a"), Atom("b"))), {"a": True, "b": False}, False),
        (Or(()), {}, False),
        (Or((Atom("a"), Atom("b"))), {"a": False, "b": True}, True),
        (
            Xor((Atom("a"), Atom("b"), Atom("c"))),
            {"a": True, "b": True, "c": True},
            True,
        ),
        (Implies(Atom("a"), Atom("b")), {"a": True, "b": False}, False),
        (Equiv(Atom("a"), Atom("b")), {"a": False, "b": False}, True),
    ],
)
def test_evaluate(expression, assignment, expected: bool) -> None:
    assert evaluate(expression, assignment) is expected


def test_convenience_constructors_preserve_boolean_identities() -> None:
    assert evaluate(all_of(), {}) is True
    assert evaluate(any_of(), {}) is False
    assert all_of(Atom("a"), Atom("b")) == And((Atom("a"), Atom("b")))
    assert any_of(Atom("a"), Atom("b")) == Or((Atom("a"), Atom("b")))


def test_atom_names_are_opaque_strings() -> None:
    assert evaluate(Atom(""), {"": True}) is True
    assert evaluate(Atom("team:read/write"), {"team:read/write": False}) is False


@pytest.mark.parametrize(
    "make_invalid",
    [
        lambda: Constant(1),
        lambda: Atom(1),
        lambda: Not(True),
        lambda: And((Atom("a"), "b")),
        lambda: Or([Atom("a")]),
        lambda: Xor((Atom("a"),)),
        lambda: Implies(Atom("a"), False),
    ],
)
def test_constructors_reject_invalid_values(make_invalid) -> None:
    with pytest.raises((TypeError, ValueError)):
        make_invalid()


def test_evaluate_requires_a_total_boolean_assignment() -> None:
    with pytest.raises(KeyError, match="missing"):
        evaluate(Atom("missing"), {})
    with pytest.raises(TypeError, match="boolean"):
        evaluate(Atom("a"), {"a": 1})
