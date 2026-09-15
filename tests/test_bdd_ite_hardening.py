from test_bdd_hardening import make_deep_chain

from authz_analyzer import BDDOperation, BinaryDecisionDiagram


def test_ite_reductions_do_not_populate_the_computed_cache():
    bdd = BinaryDecisionDiagram(["x", "y"])
    x, y = bdd.var("x"), bdd.var("y")
    assert bdd.apply(BDDOperation.ITE, x, y, y) == y
    assert bdd.apply(BDDOperation.ITE, x, bdd.TRUE, bdd.FALSE) == x
    assert bdd.apply(BDDOperation.ITE, x, bdd.FALSE, bdd.TRUE) == -x
    assert bdd.statistics()["computed_cache_size"] == 0


def test_complement_equivalent_ite_calls_share_a_cache_entry():
    bdd = BinaryDecisionDiagram(["x", "y", "z"])
    x, y, z = (bdd.var(name) for name in bdd.variables)
    first = bdd.apply(BDDOperation.ITE, x, y, z)
    before = bdd.statistics()
    second = bdd.apply(BDDOperation.ITE, -x, z, y)
    after = bdd.statistics()
    assert second == first
    assert after["computed_cache_size"] == before["computed_cache_size"]


def test_recursive_ite_handles_the_supported_variable_limit():
    bdd, root = make_deep_chain(BinaryDecisionDiagram.MAX_VARIABLES)
    last = bdd.var(bdd.variables[-1])
    assert bdd.apply(BDDOperation.OR, root, last) == last
