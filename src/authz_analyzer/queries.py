from collections.abc import Iterable
from dataclasses import replace
from time import perf_counter
from typing import Literal as TypingLiteral

from authz_analyzer.bdd import (
    BDDNodeLimitError,
    BDDOperation,
    BDDVariableLimitError,
    BinaryDecisionDiagram,
    NodeRef,
)
from authz_analyzer.compile import compile_expressions
from authz_analyzer.explain import (
    ExplanationCubeLimitError,
    all_explanations,
    one_explanation,
)
from authz_analyzer.expressions import And, Expression, Not, expression_node_count
from authz_analyzer.ir import AtomMetadata, IRDocument
from authz_analyzer.json_codec import atom_metadata_to_data
from authz_analyzer.results import (
    AnalysisError,
    Assignment,
    Diagnostics,
    DiffClassification,
    DiffOutcome,
    DiffResult,
    ErrorResult,
    ExplainOutcome,
    ExplainResult,
    Explanation,
    Literal,
    RegionEvidence,
    ReportEntry,
    ReportOutcome,
    ReportResult,
    VerifyOutcome,
    VerifyResult,
)

type QueryKind = TypingLiteral["verify", "diff", "explain", "report"]
DEFAULT_MAX_BDD_NODES = 100_000
DEFAULT_MAX_AST_NODES = 10_000
DEFAULT_EXPLANATION_LIMIT = 20
DEFAULT_MAX_EXPLANATION_CUBES = 100_000


def _require_names(*names: object) -> None:
    if any(not isinstance(name, str) for name in names):
        raise TypeError("result names must be strings")
    if any(not name for name in names):
        raise ValueError("result names must not be empty")


def _query_context(
    kind: QueryKind,
    assumptions: tuple[Expression, ...],
    expressions: tuple[Expression, ...],
    variable_order: Iterable[str] | None,
    max_bdd_nodes: int,
    max_ast_nodes: int,
) -> tuple[BinaryDecisionDiagram, tuple[NodeRef, ...], NodeRef, int] | ErrorResult:
    all_expressions = (*assumptions, *expressions)
    try:
        ast_node_count = sum(expression_node_count(item) for item in all_expressions)
    except RecursionError:
        return ErrorResult(
            kind=kind,
            status="resource_limit",
            error=AnalysisError(
                code="ast_depth_limit",
                message="AST nesting exceeds the supported recursion depth",
            ),
        )
    if ast_node_count > max_ast_nodes:
        return ErrorResult(
            kind=kind,
            status="resource_limit",
            error=AnalysisError(
                code="ast_node_limit",
                message="AST node limit exceeded",
                details={"limit": max_ast_nodes, "observed": ast_node_count},
            ),
        )
    try:
        bdd, roots = compile_expressions(
            all_expressions,
            variable_order=variable_order,
            max_nodes=max_bdd_nodes,
        )
        constraints = bdd.TRUE
        for root in roots[: len(assumptions)]:
            constraints = bdd.apply(BDDOperation.AND, constraints, root)
    except (BDDNodeLimitError, BDDVariableLimitError) as error:
        node_limit = isinstance(error, BDDNodeLimitError)
        return ErrorResult(
            kind=kind,
            status="resource_limit",
            error=AnalysisError(
                code="bdd_node_limit" if node_limit else "bdd_variable_limit",
                message=(
                    "BDD node limit exceeded"
                    if node_limit
                    else "BDD variable limit exceeded"
                ),
                details={
                    "limit": (
                        max_bdd_nodes
                        if node_limit
                        else BinaryDecisionDiagram.MAX_VARIABLES
                    )
                },
            ),
        )

    if not bdd.is_satisfiable(constraints):
        return ErrorResult(
            kind=kind,
            status="invalid_constraints",
            error=AnalysisError(
                code="unsatisfiable_assumptions",
                message="active assumptions are unsatisfiable",
                details={"activeAssumptions": len(assumptions)},
            ),
        )
    return bdd, roots[len(assumptions) :], constraints, ast_node_count


def _complete_assignment(bdd: BinaryDecisionDiagram, root: NodeRef) -> Assignment:
    partial = bdd.pick_sat(root)
    assert partial is not None
    values = {variable: partial.get(variable, False) for variable in bdd.variables}
    assert bdd.evaluate(root, values)
    return Assignment(values)


def _diagnostics(
    bdd: BinaryDecisionDiagram, ast_node_count: int, started: float
) -> Diagnostics:
    return Diagnostics(
        atom_count=len(bdd.variables),
        ast_node_count=ast_node_count,
        bdd_node_count=bdd.node_count,
        elapsed_ms=(perf_counter() - started) * 1000,
        variable_order=bdd.variables,
    )


def _resource_error(kind: QueryKind, max_bdd_nodes: int) -> ErrorResult:
    return ErrorResult(
        kind=kind,
        status="resource_limit",
        error=AnalysisError(
            code="bdd_node_limit",
            message="BDD node limit exceeded",
            details={"limit": max_bdd_nodes},
        ),
    )


def _explanation_resource_error(
    kind: QueryKind, max_explanation_cubes: int
) -> ErrorResult:
    return ErrorResult(
        kind=kind,
        status="resource_limit",
        error=AnalysisError(
            code="explanation_cube_limit",
            message="explanation cube limit exceeded",
            details={"limit": max_explanation_cubes},
        ),
    )


def verify(
    access: Expression,
    required: Expression,
    *,
    assumptions: Iterable[Expression] = (),
    variable_order: Iterable[str] | None = None,
    access_name: str = "access",
    required_name: str = "required",
    max_bdd_nodes: int = DEFAULT_MAX_BDD_NODES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> VerifyOutcome:
    """Prove that access implies required under the active assumptions."""
    _require_names(access_name, required_name)
    started = perf_counter()
    assumptions = tuple(assumptions)
    context = _query_context(
        "verify",
        assumptions,
        (access, required),
        variable_order,
        max_bdd_nodes,
        max_ast_nodes,
    )
    if isinstance(context, ErrorResult):
        return context
    bdd, (access_root, required_root), constraints, ast_node_count = context

    try:
        bypass_condition = bdd.apply(
            BDDOperation.AND,
            access_root,
            bdd.apply(BDDOperation.NOT, required_root),
        )
        bypass = bdd.apply(BDDOperation.AND, constraints, bypass_condition)
    except BDDNodeLimitError:
        return _resource_error("verify", max_bdd_nodes)
    if not bdd.is_satisfiable(bypass):
        return VerifyResult(
            status="holds",
            access=access_name,
            required=required_name,
            active_assumptions=len(assumptions),
            diagnostics=_diagnostics(bdd, ast_node_count, started),
        )

    try:
        explanation = one_explanation(bdd, constraints, bypass_condition)
    except BDDNodeLimitError:
        return _resource_error("verify", max_bdd_nodes)
    if explanation is None:
        raise RuntimeError("satisfiable bypass has no explanation")
    return VerifyResult(
        status="violated",
        access=access_name,
        required=required_name,
        counterexample=_complete_assignment(bdd, bypass),
        explanation=explanation,
        active_assumptions=len(assumptions),
        diagnostics=_diagnostics(bdd, ast_node_count, started),
    )


def diff(
    old: Expression,
    new: Expression,
    *,
    assumptions: Iterable[Expression] = (),
    variable_order: Iterable[str] | None = None,
    old_name: str = "old",
    new_name: str = "new",
    max_bdd_nodes: int = DEFAULT_MAX_BDD_NODES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> DiffOutcome:
    """Classify the semantic difference between old and new access."""
    _require_names(old_name, new_name)
    started = perf_counter()
    assumptions = tuple(assumptions)
    context = _query_context(
        "diff",
        assumptions,
        (old, new),
        variable_order,
        max_bdd_nodes,
        max_ast_nodes,
    )
    if isinstance(context, ErrorResult):
        return context
    bdd, (old_root, new_root), constraints, ast_node_count = context

    try:
        added_condition = bdd.apply(
            BDDOperation.AND,
            new_root,
            bdd.apply(BDDOperation.NOT, old_root),
        )
        removed_condition = bdd.apply(
            BDDOperation.AND,
            old_root,
            bdd.apply(BDDOperation.NOT, new_root),
        )
        added = bdd.apply(BDDOperation.AND, constraints, added_condition)
        removed = bdd.apply(BDDOperation.AND, constraints, removed_condition)
    except BDDNodeLimitError:
        return _resource_error("diff", max_bdd_nodes)
    has_added = bdd.is_satisfiable(added)
    has_removed = bdd.is_satisfiable(removed)
    classification: DiffClassification
    if has_added and has_removed:
        classification = "incomparable"
    elif has_added:
        classification = "widened"
    elif has_removed:
        classification = "narrowed"
    else:
        classification = "equivalent"
    try:
        added_explanation = (
            one_explanation(bdd, constraints, added_condition) if has_added else None
        )
        removed_explanation = (
            one_explanation(bdd, constraints, removed_condition)
            if has_removed
            else None
        )
    except BDDNodeLimitError:
        return _resource_error("diff", max_bdd_nodes)
    if has_added and added_explanation is None:
        raise RuntimeError("satisfiable added-access region has no explanation")
    if has_removed and removed_explanation is None:
        raise RuntimeError("satisfiable removed-access region has no explanation")
    return DiffResult(
        classification=classification,
        old=old_name,
        new=new_name,
        added_access=(
            RegionEvidence(_complete_assignment(bdd, added), added_explanation)
            if has_added
            else None
        ),
        removed_access=(
            RegionEvidence(_complete_assignment(bdd, removed), removed_explanation)
            if has_removed
            else None
        ),
        active_assumptions=len(assumptions),
        diagnostics=_diagnostics(bdd, ast_node_count, started),
    )


def explain(
    target: Expression,
    *,
    assumptions: Iterable[Expression] = (),
    variable_order: Iterable[str] | None = None,
    target_name: str = "target",
    limit: int = DEFAULT_EXPLANATION_LIMIT,
    max_explanation_cubes: int = DEFAULT_MAX_EXPLANATION_CUBES,
    max_bdd_nodes: int = DEFAULT_MAX_BDD_NODES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> ExplainOutcome:
    """Enumerate a bounded, deterministic prefix of all minimal explanations."""
    _require_names(target_name)
    _require_positive(limit, "limit")
    _require_positive(max_explanation_cubes, "max_explanation_cubes")
    started = perf_counter()
    assumptions = tuple(assumptions)
    context = _query_context(
        "explain",
        assumptions,
        (target,),
        variable_order,
        max_bdd_nodes,
        max_ast_nodes,
    )
    if isinstance(context, ErrorResult):
        return context
    bdd, (target_root,), constraints, ast_node_count = context
    try:
        explanations, truncated = all_explanations(
            bdd,
            constraints,
            target_root,
            limit=limit,
            max_cubes=max_explanation_cubes,
        )
    except BDDNodeLimitError:
        return _resource_error("explain", max_bdd_nodes)
    except ExplanationCubeLimitError:
        return _explanation_resource_error("explain", max_explanation_cubes)
    return ExplainResult(
        target=target_name,
        explanations=explanations,
        truncated=truncated,
        active_assumptions=len(assumptions),
        diagnostics=_diagnostics(bdd, ast_node_count, started),
    )


def _require_positive(value: object, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 1:
        raise ValueError(f"{name} must be positive")


def _invalid_name(kind: QueryKind, collection: str, name: str) -> ErrorResult:
    return ErrorResult(
        kind=kind,
        status="invalid_input",
        error=AnalysisError(
            code=f"unknown_{collection}",
            message=f"no {collection} named {name!r}",
            details={"name": name},
        ),
    )


def verify_document(
    document: IRDocument,
    access_name: str,
    required_name: str | None = None,
    *,
    max_bdd_nodes: int = DEFAULT_MAX_BDD_NODES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> VerifyOutcome:
    """Verify named access and requirement expressions from one IR document."""
    _require_names(access_name)
    required_name = access_name if required_name is None else required_name
    _require_names(required_name)
    if access_name not in document.expressions:
        return _invalid_name("verify", "expression", access_name)
    requirements = document.requirements or {}
    if required_name not in requirements:
        return _invalid_name("verify", "requirement", required_name)
    result = verify(
        document.expressions[access_name],
        requirements[required_name],
        assumptions=document.assumptions or (),
        access_name=access_name,
        required_name=required_name,
        max_bdd_nodes=max_bdd_nodes,
        max_ast_nodes=max_ast_nodes,
    )
    if isinstance(result, VerifyResult) and result.explanation is not None:
        return replace(
            result,
            explanation=_with_metadata(result.explanation, document.atoms),
        )
    return result


def diff_document(
    document: IRDocument,
    old_name: str,
    new_name: str,
    *,
    max_bdd_nodes: int = DEFAULT_MAX_BDD_NODES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> DiffOutcome:
    """Compare two named access expressions from one IR document."""
    _require_names(old_name, new_name)
    for name in (old_name, new_name):
        if name not in document.expressions:
            return _invalid_name("diff", "expression", name)
    result = diff(
        document.expressions[old_name],
        document.expressions[new_name],
        assumptions=document.assumptions or (),
        old_name=old_name,
        new_name=new_name,
        max_bdd_nodes=max_bdd_nodes,
        max_ast_nodes=max_ast_nodes,
    )
    if not isinstance(result, DiffResult):
        return result
    added = result.added_access
    removed = result.removed_access
    if added is not None and added.explanation is not None:
        added = replace(
            added,
            explanation=_with_metadata(added.explanation, document.atoms),
        )
    if removed is not None and removed.explanation is not None:
        removed = replace(
            removed,
            explanation=_with_metadata(removed.explanation, document.atoms),
        )
    return replace(result, added_access=added, removed_access=removed)


def explain_document(
    document: IRDocument,
    expression_name: str,
    *,
    limit: int = DEFAULT_EXPLANATION_LIMIT,
    max_explanation_cubes: int = DEFAULT_MAX_EXPLANATION_CUBES,
    max_bdd_nodes: int = DEFAULT_MAX_BDD_NODES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> ExplainOutcome:
    """Explain one named access expression from an IR document."""
    _require_names(expression_name)
    if expression_name not in document.expressions:
        return _invalid_name("explain", "expression", expression_name)
    result = explain(
        document.expressions[expression_name],
        assumptions=document.assumptions or (),
        target_name=expression_name,
        limit=limit,
        max_explanation_cubes=max_explanation_cubes,
        max_bdd_nodes=max_bdd_nodes,
        max_ast_nodes=max_ast_nodes,
    )
    if isinstance(result, ExplainResult):
        return replace(
            result,
            explanations=tuple(
                _with_metadata(explanation, document.atoms)
                for explanation in result.explanations
            ),
        )
    return result


def report_document(
    document: IRDocument,
    *,
    limit: int = DEFAULT_EXPLANATION_LIMIT,
    max_explanation_cubes: int = DEFAULT_MAX_EXPLANATION_CUBES,
    max_bdd_nodes: int = DEFAULT_MAX_BDD_NODES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
) -> ReportOutcome:
    """Verify every expression with a same-named requirement."""
    _require_positive(limit, "limit")
    _require_positive(max_explanation_cubes, "max_explanation_cubes")
    requirements = document.requirements or {}
    entries: list[ReportEntry] = []
    unverified: list[str] = []
    assumptions = document.assumptions or ()

    for name, access in document.expressions.items():
        required = requirements.get(name)
        if required is None:
            unverified.append(name)
            continue
        verification = verify(
            access,
            required,
            assumptions=assumptions,
            access_name=name,
            required_name=name,
            max_bdd_nodes=max_bdd_nodes,
            max_ast_nodes=max_ast_nodes,
        )
        if isinstance(verification, ErrorResult):
            return replace(verification, kind="report")

        explanations: tuple[Explanation, ...] = ()
        truncated = False
        if verification.status == "violated":
            family = explain(
                And((access, Not(required))),
                assumptions=assumptions,
                target_name=f"{name}:bypass",
                limit=limit,
                max_explanation_cubes=max_explanation_cubes,
                max_bdd_nodes=max_bdd_nodes,
                max_ast_nodes=max_ast_nodes,
            )
            if isinstance(family, ErrorResult):
                return replace(family, kind="report")
            explanations = tuple(
                _with_metadata(explanation, document.atoms)
                for explanation in family.explanations
            )
            truncated = family.truncated
        entries.append(
            ReportEntry(
                access=name,
                required=name,
                status=verification.status,
                counterexample=verification.counterexample,
                explanations=explanations,
                truncated=truncated,
                diagnostics=verification.diagnostics,
            )
        )

    return ReportResult(
        entries=tuple(entries),
        unverified_expressions=tuple(unverified),
        active_assumptions=len(assumptions),
    )


def _with_metadata(
    explanation: Explanation, atoms: dict[str, AtomMetadata] | None
) -> Explanation:
    if not atoms:
        return explanation
    return replace(
        explanation,
        literals=tuple(
            Literal(
                atom=literal.atom,
                value=literal.value,
                metadata=(
                    atom_metadata_to_data(atoms[literal.atom])
                    if literal.atom in atoms
                    else None
                ),
            )
            for literal in explanation.literals
        ),
    )


__all__ = [
    "diff",
    "diff_document",
    "explain",
    "explain_document",
    "report_document",
    "verify",
    "verify_document",
]
