from __future__ import annotations

from collections.abc import Iterator, Mapping
from itertools import product

from authz_analyzer.bdd import BDDOperation, BinaryDecisionDiagram, NodeRef

type Expression = bool | str | tuple


def atoms(expression: Expression) -> set[str]:
    if isinstance(expression, bool):
        return set()
    if isinstance(expression, str):
        return {expression}
    return set().union(*(atoms(child) for child in expression[1:]))


def evaluate(expression: Expression, assignment: Mapping[str, bool]) -> bool:
    if isinstance(expression, bool):
        return expression
    if isinstance(expression, str):
        return assignment[expression]
    operation, *children = expression
    values = [evaluate(child, assignment) for child in children]
    if operation == "not":
        return not values[0]
    if operation == "and":
        return values[0] and values[1]
    if operation == "or":
        return values[0] or values[1]
    if operation == "xor":
        return values[0] != values[1]
    if operation == "implies":
        return not values[0] or values[1]
    if operation == "equiv":
        return values[0] == values[1]
    if operation == "ite":
        return values[1] if values[0] else values[2]
    raise AssertionError(f"Unknown oracle operation: {operation}")


def assignments(variables: list[str]) -> Iterator[dict[str, bool]]:
    for values in product((False, True), repeat=len(variables)):
        yield dict(zip(variables, values, strict=True))


def compile_expression(
    expression: Expression, variables: list[str] | None = None
) -> tuple[BinaryDecisionDiagram, NodeRef]:
    order = variables if variables is not None else sorted(atoms(expression))
    bdd = BinaryDecisionDiagram(order)

    def compile_node(node: Expression) -> NodeRef:
        if isinstance(node, bool):
            return bdd.TRUE if node else bdd.FALSE
        if isinstance(node, str):
            return bdd.var(node)
        operation, *children = node
        refs = [compile_node(child) for child in children]
        return bdd.apply(BDDOperation(operation), *refs)

    return bdd, compile_node(expression)
