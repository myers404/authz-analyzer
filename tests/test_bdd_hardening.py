import pytest
from bdd_oracle import compile_expression

from authz_analyzer import (
    BDDNodeLimitError,
    BDDOperation,
    BDDVariableLimitError,
    BinaryDecisionDiagram,
)


def test_pick_sat_is_deterministic_and_prefers_false_branches():
    bdd, root = compile_expression(("or", "x", "y"), ["x", "y"])
    assert bdd.pick_sat(root) == {"x": False, "y": True}
    assert bdd.pick_sat(root) == bdd.pick_sat(root)
    assert bdd.pick_sat(bdd.FALSE) is None
    assert bdd.pick_sat(bdd.TRUE) == {}


def test_restrict_rejects_non_boolean_assignments():
    bdd, root = compile_expression("x")
    for value in (0, 1, "false", None):
        with pytest.raises(TypeError, match="boolean"):
            bdd.restrict(root, {"x": value})


def test_evaluate_rejects_non_boolean_assignments():
    bdd, root = compile_expression("x")
    with pytest.raises(TypeError, match="boolean"):
        bdd.evaluate(root, {"x": 1})


def test_computed_cache_can_be_inspected_and_cleared():
    bdd = BinaryDecisionDiagram(["x", "y"])
    x, y = bdd.var("x"), bdd.var("y")
    bdd.apply(BDDOperation.AND, x, y)
    assert bdd.statistics()["computed_cache_size"] > 0
    before = bdd.statistics()
    bdd.apply(BDDOperation.AND, y, x)
    after = bdd.statistics()
    assert after["computed_cache_size"] == before["computed_cache_size"]
    bdd.clear_computed_cache()
    assert bdd.statistics()["computed_cache_size"] == 0


def test_computed_cache_can_be_bounded():
    bdd = BinaryDecisionDiagram(["a", "b", "c"], max_computed_cache_entries=1)
    a, b, c = (bdd.var(name) for name in bdd.variables)
    bdd.apply(BDDOperation.AND, a, b)
    bdd.apply(BDDOperation.OR, a, c)
    assert bdd.statistics()["computed_cache_size"] <= 1


def test_node_limit_fails_before_mutating_the_manager():
    bdd = BinaryDecisionDiagram(["x", "y"], max_nodes=1)
    bdd.var("x")
    before = bdd.node_count
    with pytest.raises(BDDNodeLimitError):
        bdd.var("y")
    assert bdd.node_count == before


def make_deep_chain(size):
    variables = [f"x{i}" for i in range(size)]
    bdd = BinaryDecisionDiagram(variables)
    root = bdd.TRUE
    for level in reversed(range(size)):
        root = bdd._find_or_add(level, bdd.FALSE, root)
    return bdd, root


def test_recursive_operations_handle_the_supported_variable_limit():
    bdd, root = make_deep_chain(BinaryDecisionDiagram.MAX_VARIABLES)
    assert bdd.pick_sat(root) is not None
    assert bdd.restrict(root, {"x255": False}) == bdd.FALSE
    assert bdd.exists(root, {"x255"}) != bdd.FALSE


def test_variable_limit_rejects_unsupported_universe():
    variables = [f"x{i}" for i in range(BinaryDecisionDiagram.MAX_VARIABLES + 1)]
    with pytest.raises(BDDVariableLimitError, match="256"):
        BinaryDecisionDiagram(variables)
