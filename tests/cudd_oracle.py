def cudd_value(bdd, root, assignment):
    value = bdd.let(assignment, root) if assignment else root
    assert value == bdd.true or value == bdd.false
    return value == bdd.true
