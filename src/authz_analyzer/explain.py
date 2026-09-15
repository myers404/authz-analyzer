from dataclasses import dataclass

from authz_analyzer.bdd import BDDOperation, BinaryDecisionDiagram, NodeRef
from authz_analyzer.results import Explanation, Literal

type Cube = tuple[int, int]


class ExplanationCubeLimitError(RuntimeError):
    pass


@dataclass(slots=True)
class _Budget:
    limit: int
    used: int = 0

    def charge(self) -> None:
        self.used += 1
        if self.used > self.limit:
            raise ExplanationCubeLimitError


def one_explanation(
    bdd: BinaryDecisionDiagram, constraints: NodeRef, target: NodeRef
) -> Explanation | None:
    """Return one deterministic subset-minimal explanation for target under constraints."""
    satisfying = bdd.apply(BDDOperation.AND, constraints, target)
    witness = bdd.pick_sat(satisfying)
    if witness is None:
        return None

    candidate = {name: witness.get(name, False) for name in bdd.variables}
    bad = bdd.apply(BDDOperation.AND, constraints, -target)
    for variable in reversed(bdd.variables):
        value = candidate.pop(variable)
        if bdd.restrict(bad, candidate) != bdd.FALSE:
            candidate[variable] = value

    _validate_explanation(bdd, constraints, bad, candidate)
    return _to_explanation(bdd, _assignment_to_cube(bdd, candidate))


def all_explanations(
    bdd: BinaryDecisionDiagram,
    constraints: NodeRef,
    target: NodeRef,
    *,
    limit: int,
    max_cubes: int,
) -> tuple[tuple[Explanation, ...], bool]:
    """Return a bounded prefix of every subset-minimal explanation."""
    if bdd.apply(BDDOperation.AND, constraints, target) == bdd.FALSE:
        return (), False
    implication = bdd.apply(BDDOperation.OR, -constraints, target)
    cubes = _prime_implicants(bdd, implication, max_cubes)
    consistent = [
        cube
        for cube in cubes
        if bdd.restrict(constraints, _cube_assignment(bdd, cube)) != bdd.FALSE
    ]
    bad = bdd.apply(BDDOperation.AND, constraints, -target)
    for cube in consistent:
        _validate_explanation(bdd, constraints, bad, _cube_assignment(bdd, cube))
    consistent.sort(key=lambda cube: _cube_sort_key(bdd, cube))
    truncated = len(consistent) > limit
    return tuple(_to_explanation(bdd, cube) for cube in consistent[:limit]), truncated


def _prime_implicants(
    bdd: BinaryDecisionDiagram, root: NodeRef, max_cubes: int
) -> tuple[Cube, ...]:
    levels = {variable: level for level, variable in enumerate(bdd.variables)}
    memo: dict[NodeRef, tuple[Cube, ...]] = {}
    budget = _Budget(max_cubes)

    def visit(ref: NodeRef) -> tuple[Cube, ...]:
        if ref == bdd.FALSE:
            return ()
        if ref == bdd.TRUE:
            return ((0, 0),)
        if ref in memo:
            return memo[ref]

        variable = bdd.support(ref)[0]
        level = levels[variable]
        low = bdd.restrict(ref, {variable: False})
        high = bdd.restrict(ref, {variable: True})
        shared = bdd.apply(BDDOperation.AND, low, high)

        family: list[Cube] = []
        for cube in visit(shared):
            _insert_minimal(family, cube, budget)
        for cube in visit(low):
            _insert_minimal(family, _with_literal(cube, level, False), budget)
        for cube in visit(high):
            _insert_minimal(family, _with_literal(cube, level, True), budget)
        memo[ref] = tuple(family)
        return memo[ref]

    return visit(root)


def _insert_minimal(family: list[Cube], candidate: Cube, budget: _Budget) -> None:
    budget.charge()
    if any(_is_subset(existing, candidate) for existing in family):
        return
    family[:] = [item for item in family if not _is_subset(candidate, item)]
    family.append(candidate)


def _is_subset(left: Cube, right: Cube) -> bool:
    left_positive, left_negative = left
    right_positive, right_negative = right
    return (
        left_positive & right_positive == left_positive
        and left_negative & right_negative == left_negative
    )


def _with_literal(cube: Cube, level: int, value: bool) -> Cube:
    positive, negative = cube
    bit = 1 << level
    if value:
        return positive | bit, negative
    return positive, negative | bit


def _assignment_to_cube(
    bdd: BinaryDecisionDiagram, assignment: dict[str, bool]
) -> Cube:
    positive = 0
    negative = 0
    for level, variable in enumerate(bdd.variables):
        if variable not in assignment:
            continue
        if assignment[variable]:
            positive |= 1 << level
        else:
            negative |= 1 << level
    return positive, negative


def _cube_assignment(bdd: BinaryDecisionDiagram, cube: Cube) -> dict[str, bool]:
    positive, negative = cube
    return {
        variable: bool(positive & (1 << level))
        for level, variable in enumerate(bdd.variables)
        if (positive | negative) & (1 << level)
    }


def _to_explanation(bdd: BinaryDecisionDiagram, cube: Cube) -> Explanation:
    assignment = _cube_assignment(bdd, cube)
    return Explanation(
        literals=tuple(
            Literal(variable, assignment[variable])
            for variable in bdd.variables
            if variable in assignment
        )
    )


def _cube_sort_key(
    bdd: BinaryDecisionDiagram, cube: Cube
) -> tuple[int, tuple[tuple[int, bool], ...]]:
    assignment = _cube_assignment(bdd, cube)
    ordered = tuple(
        (level, assignment[variable])
        for level, variable in enumerate(bdd.variables)
        if variable in assignment
    )
    return len(ordered), ordered


def _validate_explanation(
    bdd: BinaryDecisionDiagram,
    constraints: NodeRef,
    bad: NodeRef,
    assignment: dict[str, bool],
) -> None:
    if bdd.restrict(constraints, assignment) == bdd.FALSE:
        raise RuntimeError("explanation is inconsistent with active assumptions")
    if bdd.restrict(bad, assignment) != bdd.FALSE:
        raise RuntimeError("explanation is not sufficient")
    for variable in assignment:
        reduced = dict(assignment)
        del reduced[variable]
        if bdd.restrict(bad, reduced) == bdd.FALSE:
            raise RuntimeError("explanation is not subset-minimal")


__all__ = [
    "ExplanationCubeLimitError",
    "all_explanations",
    "one_explanation",
]
