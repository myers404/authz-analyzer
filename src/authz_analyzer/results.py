from dataclasses import dataclass
from typing import Literal as TypingLiteral

type VerifyStatus = TypingLiteral["holds", "violated"]
type DiffClassification = TypingLiteral[
    "equivalent", "widened", "narrowed", "incomparable"
]
type ErrorStatus = TypingLiteral[
    "invalid_input", "invalid_constraints", "resource_limit", "internal_error"
]


@dataclass(frozen=True, slots=True)
class Assignment:
    values: dict[str, bool]
    complete: bool = True


@dataclass(frozen=True, slots=True)
class AnalysisError:
    code: str
    message: str
    pointer: str | None = None
    line: int | None = None
    column: int | None = None
    details: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class Diagnostics:
    atom_count: int
    ast_node_count: int
    bdd_node_count: int
    elapsed_ms: float
    variable_order: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Literal:
    atom: str
    value: bool
    metadata: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class Explanation:
    literals: tuple[Literal, ...]
    minimality: TypingLiteral["subset-minimal"] = "subset-minimal"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    status: VerifyStatus
    access: str
    required: str
    counterexample: Assignment | None = None
    explanation: Explanation | None = None
    active_assumptions: int = 0
    diagnostics: Diagnostics | None = None


@dataclass(frozen=True, slots=True)
class RegionEvidence:
    counterexample: Assignment
    explanation: Explanation | None = None


@dataclass(frozen=True, slots=True)
class ExplainResult:
    target: str
    explanations: tuple[Explanation, ...]
    truncated: bool
    active_assumptions: int = 0
    diagnostics: Diagnostics | None = None
    status: TypingLiteral["completed"] = "completed"


@dataclass(frozen=True, slots=True)
class ReportEntry:
    access: str
    required: str
    status: VerifyStatus
    explanations: tuple[Explanation, ...] = ()
    truncated: bool = False
    counterexample: Assignment | None = None
    diagnostics: Diagnostics | None = None


@dataclass(frozen=True, slots=True)
class ReportResult:
    entries: tuple[ReportEntry, ...]
    unverified_expressions: tuple[str, ...]
    active_assumptions: int = 0
    status: TypingLiteral["completed"] = "completed"


@dataclass(frozen=True, slots=True)
class DiffResult:
    classification: DiffClassification
    old: str
    new: str
    added_access: RegionEvidence | None = None
    removed_access: RegionEvidence | None = None
    active_assumptions: int = 0
    diagnostics: Diagnostics | None = None
    status: TypingLiteral["completed"] = "completed"


@dataclass(frozen=True, slots=True)
class ValidateResult:
    status: TypingLiteral["valid"] = "valid"


@dataclass(frozen=True, slots=True)
class ErrorResult:
    kind: TypingLiteral["verify", "diff", "explain", "report", "validate"]
    status: ErrorStatus
    error: AnalysisError
    diagnostics: Diagnostics | None = None


type VerifyOutcome = VerifyResult | ErrorResult
type DiffOutcome = DiffResult | ErrorResult
type ExplainOutcome = ExplainResult | ErrorResult
type ReportOutcome = ReportResult | ErrorResult
type Result = (
    VerifyResult
    | DiffResult
    | ExplainResult
    | ReportResult
    | ValidateResult
    | ErrorResult
)


def _assignment_to_data(assignment: Assignment) -> dict[str, object]:
    return {
        "complete": assignment.complete,
        "values": dict(assignment.values),
    }


def _diagnostics_to_data(diagnostics: Diagnostics) -> dict[str, object]:
    return {
        "atomCount": diagnostics.atom_count,
        "astNodeCount": diagnostics.ast_node_count,
        "bddNodeCount": diagnostics.bdd_node_count,
        "elapsedMs": diagnostics.elapsed_ms,
        "variableOrder": list(diagnostics.variable_order),
    }


def _explanation_to_data(explanation: Explanation) -> dict[str, object]:
    literals: list[dict[str, object]] = []
    for literal in explanation.literals:
        item: dict[str, object] = {"atom": literal.atom, "value": literal.value}
        if literal.metadata is not None:
            item["metadata"] = literal.metadata
        literals.append(item)
    return {"minimality": explanation.minimality, "literals": literals}


def result_to_data(result: Result) -> dict[str, object]:
    if isinstance(result, VerifyResult):
        data: dict[str, object] = {
            "resultVersion": "1",
            "kind": "verify",
            "status": result.status,
            "access": result.access,
            "required": result.required,
            "activeAssumptions": result.active_assumptions,
        }
        if result.counterexample is not None:
            data["counterexample"] = _assignment_to_data(result.counterexample)
        if result.explanation is not None:
            data["explanation"] = _explanation_to_data(result.explanation)
        if result.diagnostics is not None:
            data["diagnostics"] = _diagnostics_to_data(result.diagnostics)
        return data

    if isinstance(result, DiffResult):
        data = {
            "resultVersion": "1",
            "kind": "diff",
            "status": result.status,
            "old": result.old,
            "new": result.new,
            "classification": result.classification,
            "activeAssumptions": result.active_assumptions,
        }
        if result.added_access is not None:
            added: dict[str, object] = {
                "counterexample": _assignment_to_data(
                    result.added_access.counterexample
                )
            }
            if result.added_access.explanation is not None:
                added["explanation"] = _explanation_to_data(
                    result.added_access.explanation
                )
            data["addedAccess"] = added
        if result.removed_access is not None:
            removed: dict[str, object] = {
                "counterexample": _assignment_to_data(
                    result.removed_access.counterexample
                )
            }
            if result.removed_access.explanation is not None:
                removed["explanation"] = _explanation_to_data(
                    result.removed_access.explanation
                )
            data["removedAccess"] = removed
        if result.diagnostics is not None:
            data["diagnostics"] = _diagnostics_to_data(result.diagnostics)
        return data

    if isinstance(result, ExplainResult):
        data = {
            "resultVersion": "1",
            "kind": "explain",
            "status": result.status,
            "target": result.target,
            "explanations": [
                _explanation_to_data(explanation) for explanation in result.explanations
            ],
            "truncated": result.truncated,
            "activeAssumptions": result.active_assumptions,
        }
        if result.diagnostics is not None:
            data["diagnostics"] = _diagnostics_to_data(result.diagnostics)
        return data

    if isinstance(result, ReportResult):
        entries: list[dict[str, object]] = []
        for entry in result.entries:
            item: dict[str, object] = {
                "access": entry.access,
                "required": entry.required,
                "status": entry.status,
                "explanations": [
                    _explanation_to_data(explanation)
                    for explanation in entry.explanations
                ],
                "truncated": entry.truncated,
            }
            if entry.counterexample is not None:
                item["counterexample"] = _assignment_to_data(entry.counterexample)
            if entry.diagnostics is not None:
                item["diagnostics"] = _diagnostics_to_data(entry.diagnostics)
            entries.append(item)
        return {
            "resultVersion": "1",
            "kind": "report",
            "status": result.status,
            "entries": entries,
            "unverifiedExpressions": list(result.unverified_expressions),
            "activeAssumptions": result.active_assumptions,
        }

    if isinstance(result, ValidateResult):
        return {
            "resultVersion": "1",
            "kind": "validate",
            "status": result.status,
        }

    error: dict[str, object] = {
        "code": result.error.code,
        "message": result.error.message,
    }
    if result.error.details is not None:
        error["details"] = result.error.details
    for field in ("pointer", "line", "column"):
        value = getattr(result.error, field)
        if value is not None:
            error[field] = value
    data = {
        "resultVersion": "1",
        "kind": result.kind,
        "status": result.status,
        "error": error,
    }
    if result.diagnostics is not None:
        data["diagnostics"] = _diagnostics_to_data(result.diagnostics)
    return data


__all__ = [
    "AnalysisError",
    "Assignment",
    "DiffClassification",
    "DiffOutcome",
    "DiffResult",
    "Diagnostics",
    "ErrorResult",
    "ExplainOutcome",
    "ExplainResult",
    "Explanation",
    "Literal",
    "RegionEvidence",
    "ReportEntry",
    "ReportOutcome",
    "ReportResult",
    "Result",
    "VerifyOutcome",
    "VerifyResult",
    "ValidateResult",
    "result_to_data",
]
