import pytest

from authz_analyzer import BDDOperation, BinaryDecisionDiagram

from bdd_oracle import assignments, compile_expression, evaluate


def assert_semantics(bdd, root, expression):
    variables = list(bdd.variables)
    for assignment in assignments(variables):
        assert bdd.evaluate(root, assignment) == evaluate(expression, assignment)


@pytest.mark.parametrize(
    ("operation", "expression"),
    [
        (BDDOperation.AND, ("and", "x", "y")),
        (BDDOperation.OR, ("or", "x", "y")),
        (BDDOperation.XOR, ("xor", "x", "y")),
        (BDDOperation.IMPLIES, ("implies", "x", "y")),
        (BDDOperation.EQUIV, ("equiv", "x", "y")),
    ],
)
def test_binary_operations(operation, expression):
    bdd = BinaryDecisionDiagram(["x", "y"])
    root = bdd.apply(operation, bdd.var("x"), bdd.var("y"))
    assert_semantics(bdd, root, expression)


def test_not_and_ite():
    bdd = BinaryDecisionDiagram(["x", "y", "z"])
    x, y, z = (bdd.var(name) for name in bdd.variables)
    assert_semantics(bdd, bdd.apply(BDDOperation.NOT, x), ("not", "x"))
    assert_semantics(bdd, bdd.apply(BDDOperation.ITE, x, y, z), ("ite", "x", "y", "z"))


def test_apply_rejects_wrong_arity():
    bdd = BinaryDecisionDiagram(["x"])
    x = bdd.var("x")
    invalid_calls = [
        (BDDOperation.NOT, ()),
        (BDDOperation.NOT, (x, x)),
        (BDDOperation.AND, (x,)),
        (BDDOperation.AND, (x, x, x)),
        (BDDOperation.ITE, (x, x)),
        (BDDOperation.ITE, (x, x, x, x)),
    ]
    for operation, operands in invalid_calls:
        with pytest.raises(ValueError, match="requires"):
            bdd.apply(operation, *operands)


def test_reduction_and_canonicity():
    bdd = BinaryDecisionDiagram(["x", "y"])
    x, y = bdd.var("x"), bdd.var("y")
    assert bdd.apply(BDDOperation.AND, x, x) == x
    assert bdd.apply(BDDOperation.OR, x, x) == x
    assert bdd.apply(BDDOperation.NOT, bdd.apply(BDDOperation.NOT, x)) == x
    assert bdd.apply(BDDOperation.AND, x, y) == bdd.apply(BDDOperation.AND, y, x)
    assert bdd.apply(BDDOperation.OR, x, -x) == bdd.TRUE
    assert bdd.apply(BDDOperation.AND, x, -x) == bdd.FALSE


def test_support_is_in_variable_order():
    expression = ("and", "z", ("or", "x", "y"))
    bdd, root = compile_expression(expression, ["x", "y", "z"])
    assert bdd.support(root) == ("x", "y", "z")


def test_restrict_applies_assignments_after_a_true_branch():
    bdd, root = compile_expression(("and", "x", "y"))
    restricted = bdd.restrict(root, {"x": True, "y": False})
    assert restricted == bdd.FALSE


def test_exists_eliminates_a_string_variable():
    bdd, root = compile_expression(("and", "x", "y"))
    assert bdd.exists(root, {"x"}) == bdd.var("y")


def test_forall_eliminates_a_string_variable():
    bdd, root = compile_expression(("and", "x", "y"))
    assert bdd.forall(root, {"x"}) == bdd.FALSE


def test_invalid_references_are_rejected():
    bdd = BinaryDecisionDiagram(["x"])
    for ref in (0, 2, -2):
        with pytest.raises(ValueError):
            bdd.is_satisfiable(ref)


def test_invalid_variables_are_rejected():
    with pytest.raises(TypeError):
        BinaryDecisionDiagram([1])
    with pytest.raises(ValueError, match="unique"):
        BinaryDecisionDiagram(["x", "x"])


def test_node_construction_rejects_unordered_children():
    bdd = BinaryDecisionDiagram(["x", "y"])
    x = bdd.var("x")
    with pytest.raises(ValueError, match="ordered"):
        bdd._find_or_add(1, bdd.FALSE, x)
