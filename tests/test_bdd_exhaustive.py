from bdd_oracle import assignments

from authz_analyzer import BDDOperation, BinaryDecisionDiagram


def dnf_bdd(bdd, variables, outputs):
    result = bdd.FALSE
    for assignment, output in zip(assignments(variables), outputs, strict=True):
        if not output:
            continue
        term = bdd.TRUE
        for variable in variables:
            literal = bdd.var(variable)
            if not assignment[variable]:
                literal = -literal
            term = bdd.apply(BDDOperation.AND, term, literal)
        result = bdd.apply(BDDOperation.OR, result, term)
    return result


def cnf_bdd(bdd, variables, outputs):
    result = bdd.TRUE
    for assignment, output in zip(assignments(variables), outputs, strict=True):
        if output:
            continue
        clause = bdd.FALSE
        for variable in variables:
            literal = bdd.var(variable)
            if assignment[variable]:
                literal = -literal
            clause = bdd.apply(BDDOperation.OR, clause, literal)
        result = bdd.apply(BDDOperation.AND, result, clause)
    return result


def test_public_api_for_all_three_variable_boolean_functions():
    variables = ["a", "b", "c"]
    all_assignments = list(assignments(variables))
    for function in range(256):
        outputs = tuple(bool(function & (1 << row)) for row in range(8))
        truth_table = {
            tuple(assignment[variable] for variable in variables): output
            for assignment, output in zip(all_assignments, outputs, strict=True)
        }

        bdd = BinaryDecisionDiagram(variables)
        dnf_root = dnf_bdd(bdd, variables, outputs)
        cnf_root = cnf_bdd(bdd, variables, outputs)
        assert dnf_root == cnf_root
        assert [bdd.evaluate(dnf_root, a) for a in all_assignments] == list(outputs)
        assert bdd.is_satisfiable(dnf_root) == any(outputs)

        witness = bdd.pick_sat(dnf_root)
        if witness is None:
            assert not any(outputs)
        else:
            matching_outputs = [
                output
                for assignment, output in zip(all_assignments, outputs, strict=True)
                if assignment.items() >= witness.items()
            ]
            assert matching_outputs and all(matching_outputs)

        expected_support = []
        for variable in variables:
            remaining = [name for name in variables if name != variable]
            restricted = {
                value: bdd.restrict(dnf_root, {variable: value})
                for value in (False, True)
            }
            exists = bdd.exists(dnf_root, [variable])
            forall = bdd.forall(dnf_root, [variable])
            depends_on_variable = False

            for partial in assignments(remaining):
                expected = []
                for value in (False, True):
                    full = partial | {variable: value}
                    result = truth_table[tuple(full[name] for name in variables)]
                    expected.append(result)
                    assert bdd.evaluate(restricted[value], partial) == result
                assert bdd.evaluate(exists, partial) == any(expected)
                assert bdd.evaluate(forall, partial) == all(expected)
                depends_on_variable |= expected[0] != expected[1]

            if depends_on_variable:
                expected_support.append(variable)

        assert bdd.support(dnf_root) == tuple(expected_support)
