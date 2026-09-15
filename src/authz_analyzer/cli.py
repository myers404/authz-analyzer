import argparse
import json
from importlib.metadata import version
from pathlib import Path
from typing import Literal as TypingLiteral

from authz_analyzer.expressions import Expression
from authz_analyzer.ir import IRDocument
from authz_analyzer.json_codec import IRCodecError, load_document
from authz_analyzer.lexer import ExpressionSyntaxError
from authz_analyzer.parser import parse
from authz_analyzer.queries import (
    DEFAULT_EXPLANATION_LIMIT,
    DEFAULT_MAX_AST_NODES,
    DEFAULT_MAX_BDD_NODES,
    DEFAULT_MAX_EXPLANATION_CUBES,
    diff,
    diff_document,
    explain,
    explain_document,
    report_document,
    verify,
    verify_document,
)
from authz_analyzer.results import (
    AnalysisError,
    DiffResult,
    ErrorResult,
    ExplainResult,
    Explanation,
    Literal,
    ReportResult,
    Result,
    ValidateResult,
    VerifyResult,
    result_to_data,
)

MAX_INPUT_BYTES = 1_000_000
type Command = TypingLiteral["validate", "verify", "diff", "explain", "report"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authz", description="Analyze Boolean authorization policies"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('authz-analyzer')}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate a Boolean IR document")
    validate.add_argument("document", type=Path)
    _add_output_option(validate)

    verify = commands.add_parser("verify", help="verify an access requirement")
    verify.add_argument("document", type=Path, nargs="?")
    access = verify.add_mutually_exclusive_group()
    access.add_argument("--access", help="named access expression")
    access.add_argument("--access-expr", help="access expression string")
    required = verify.add_mutually_exclusive_group()
    required.add_argument(
        "--required",
        help="named requirement (defaults to the access expression name)",
    )
    required.add_argument("--required-expr", help="requirement expression string")
    _add_query_options(verify)

    diff = commands.add_parser("diff", help="compare two access expressions")
    diff.add_argument("document", type=Path, nargs="?")
    old = diff.add_mutually_exclusive_group()
    old.add_argument("--old", help="old named expression")
    old.add_argument("--old-expr", help="old expression string")
    new = diff.add_mutually_exclusive_group()
    new.add_argument("--new", help="new named expression")
    new.add_argument("--new-expr", help="new expression string")
    _add_query_options(diff)

    explain = commands.add_parser(
        "explain", help="enumerate minimal explanations for an expression"
    )
    explain.add_argument("document", type=Path, nargs="?")
    target = explain.add_mutually_exclusive_group()
    target.add_argument("--expression", help="named expression")
    target.add_argument("--expr", help="expression string")
    _add_explanation_options(explain)

    report = commands.add_parser(
        "report", help="verify all expressions with matching requirements"
    )
    report.add_argument("document", type=Path)
    _add_explanation_options(report)
    return parser


def _add_output_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json"), default="text")


def _add_query_options(parser: argparse.ArgumentParser) -> None:
    _add_output_option(parser)
    parser.add_argument(
        "--assume",
        action="append",
        default=[],
        metavar="EXPR",
        help="additional assumption expression (repeatable)",
    )
    parser.add_argument(
        "--max-bdd-nodes",
        type=_positive_integer,
        default=DEFAULT_MAX_BDD_NODES,
        metavar="N",
    )
    parser.add_argument(
        "--max-ast-nodes",
        type=_positive_integer,
        default=DEFAULT_MAX_AST_NODES,
        metavar="N",
    )


def _add_explanation_options(parser: argparse.ArgumentParser) -> None:
    _add_query_options(parser)
    parser.add_argument(
        "--limit",
        type=_positive_integer,
        default=DEFAULT_EXPLANATION_LIMIT,
        metavar="N",
    )
    parser.add_argument(
        "--max-explanation-cubes",
        type=_positive_integer,
        default=DEFAULT_MAX_EXPLANATION_CUBES,
        metavar="N",
    )


def _positive_integer(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _load(path: Path, kind: Command) -> IRDocument | ErrorResult:
    try:
        source = path.read_bytes()
    except OSError as error:
        return ErrorResult(
            kind=kind,
            status="invalid_input",
            error=AnalysisError(code="input_read_error", message=str(error)),
        )
    if len(source) > MAX_INPUT_BYTES:
        return ErrorResult(
            kind=kind,
            status="resource_limit",
            error=AnalysisError(
                code="input_size_limit",
                message="input size limit exceeded",
                details={"limit": MAX_INPUT_BYTES, "observed": len(source)},
            ),
        )
    try:
        return load_document(source)
    except IRCodecError as error:
        return ErrorResult(
            kind=kind,
            status="invalid_input",
            error=AnalysisError(
                code=error.code,
                message=error.message,
                pointer=error.pointer,
                line=error.line,
                column=error.column,
            ),
        )
    except RecursionError:
        return ErrorResult(
            kind=kind,
            status="resource_limit",
            error=AnalysisError(
                code="input_nesting_limit",
                message="input nesting limit exceeded",
            ),
        )


def _parse_expression(
    source: str, kind: Command, argument: str
) -> Expression | ErrorResult:
    try:
        return parse(source)
    except ExpressionSyntaxError as error:
        return ErrorResult(
            kind=kind,
            status="invalid_input",
            error=AnalysisError(
                code=error.code,
                message=str(error),
                line=error.line,
                column=error.column,
                details={"argument": argument},
            ),
        )
    except RecursionError:
        return ErrorResult(
            kind=kind,
            status="resource_limit",
            error=AnalysisError(
                code="expression_nesting_limit",
                message=f"{argument} nesting limit exceeded",
                details={"argument": argument},
            ),
        )


def _parse_assumptions(
    sources: list[str], kind: Command
) -> tuple[Expression, ...] | ErrorResult:
    assumptions: list[Expression] = []
    for index, source in enumerate(sources, 1):
        parsed = _parse_expression(source, kind, f"--assume #{index}")
        if isinstance(parsed, ErrorResult):
            return parsed
        assumptions.append(parsed)
    return tuple(assumptions)


def _add_assumptions(
    document: IRDocument, assumptions: tuple[Expression, ...]
) -> IRDocument:
    document.assumptions = (*(document.assumptions or ()), *assumptions)
    return document


def _text(result: Result) -> str:
    if isinstance(result, ErrorResult):
        return f"ERROR [{result.status}/{result.error.code}]: {result.error.message}"
    if isinstance(result, ValidateResult):
        return "VALID"
    if isinstance(result, VerifyResult):
        if result.status == "holds":
            return (
                f"HOLDS: access {result.access!r} implies requirement "
                f"{result.required!r}"
            )
        if result.counterexample is None:
            raise RuntimeError("violated verification is missing a counterexample")
        lines = [
            f"VIOLATED: access {result.access!r} does not imply requirement "
            f"{result.required!r}",
            f"counterexample: {_assignment(result.counterexample.values)}",
        ]
        if result.explanation is not None:
            lines.extend(
                _explanation_lines("one subset-minimal explanation", result.explanation)
            )
        return "\n".join(lines)

    if isinstance(result, ExplainResult):
        lines = [
            f"EXPLANATIONS: {result.target!r}",
            f"active assumptions: {result.active_assumptions}",
        ]
        for index, explanation in enumerate(result.explanations, 1):
            lines.extend(_explanation_lines(str(index), explanation))
        if not result.explanations:
            lines.append("none")
        if result.truncated:
            lines.append("truncated: more explanations exist")
        return "\n".join(lines)

    if isinstance(result, ReportResult):
        lines = [
            "AUTHORIZATION REPORT",
            f"active assumptions: {result.active_assumptions}",
        ]
        for entry in result.entries:
            lines.append(
                f"{entry.status.upper()}: {entry.access!r} -> {entry.required!r}"
            )
            if entry.counterexample is not None:
                lines.append(
                    f"  counterexample: {_assignment(entry.counterexample.values)}"
                )
            for index, explanation in enumerate(entry.explanations, 1):
                lines.extend(_explanation_lines(f"  explanation {index}", explanation))
            if entry.truncated:
                lines.append("  truncated: more explanations exist")
        for name in result.unverified_expressions:
            lines.append(f"UNVERIFIED: {name!r} has no matching requirement")
        return "\n".join(lines)

    lines = [result.classification.upper()]
    if result.added_access is not None:
        lines.append(
            "added-access example: "
            + _assignment(result.added_access.counterexample.values)
        )
        if result.added_access.explanation is not None:
            lines.extend(
                _explanation_lines(
                    "one subset-minimal added-access explanation",
                    result.added_access.explanation,
                )
            )
    if result.removed_access is not None:
        lines.append(
            "removed-access example: "
            + _assignment(result.removed_access.counterexample.values)
        )
        if result.removed_access.explanation is not None:
            lines.extend(
                _explanation_lines(
                    "one subset-minimal removed-access explanation",
                    result.removed_access.explanation,
                )
            )
    return "\n".join(lines)


def _explanation_lines(label: str, explanation: Explanation) -> list[str]:
    formula = " & ".join(_literal_text(item) for item in explanation.literals) or "true"
    lines = [f"{label}: {formula}"]
    for literal in explanation.literals:
        context = _literal_context(literal)
        if context:
            lines.append(f"  {literal.atom}: {context}")
    return lines


def _literal_text(literal: Literal) -> str:
    return literal.atom if literal.value else f"!{literal.atom}"


def _literal_context(literal: Literal) -> str:
    metadata = literal.metadata or {}
    details = [
        str(metadata[field])
        for field in ("description", "category")
        if field in metadata
    ]
    if "owner" in metadata:
        details.append(f"owner={metadata['owner']}")
    provenance = metadata.get("provenance")
    if isinstance(provenance, list) and provenance:
        source = provenance[0]
        if isinstance(source, dict) and "source" in source:
            location = str(source["source"])
            if "line" in source:
                location += f":{source['line']}"
            details.append(location)
    return "; ".join(details)


def _assignment(values: dict[str, bool]) -> str:
    return ", ".join(f"{name}={str(value).lower()}" for name, value in values.items())


def _exit_code(result: Result) -> int:
    if isinstance(result, ErrorResult):
        return 2
    if isinstance(result, VerifyResult):
        return 0 if result.status == "holds" else 1
    if isinstance(result, DiffResult):
        return 0 if result.classification == "equivalent" else 1
    if isinstance(result, ReportResult):
        return 1 if any(entry.status == "violated" for entry in result.entries) else 0
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    assumptions = (
        _parse_assumptions(args.assume, args.command)
        if args.command != "validate"
        else ()
    )
    if isinstance(assumptions, ErrorResult):
        result: Result = assumptions
    elif args.command == "validate":
        document = _load(args.document, args.command)
        result = document if isinstance(document, ErrorResult) else ValidateResult()
    elif args.command == "verify" and args.access_expr is not None:
        if args.document is not None or args.required_expr is None:
            parser.error(
                "direct verification requires --access-expr and --required-expr "
                "without a document"
            )
        access = _parse_expression(args.access_expr, "verify", "--access-expr")
        required = _parse_expression(args.required_expr, "verify", "--required-expr")
        if isinstance(access, ErrorResult):
            result = access
        elif isinstance(required, ErrorResult):
            result = required
        else:
            result = verify(
                access,
                required,
                assumptions=assumptions,
                access_name=args.access_expr,
                required_name=args.required_expr,
                max_bdd_nodes=args.max_bdd_nodes,
                max_ast_nodes=args.max_ast_nodes,
            )
    elif args.command == "verify":
        if (
            args.document is None
            or args.access is None
            or args.required_expr is not None
        ):
            parser.error("named verification requires a document and --access")
        document = _load(args.document, "verify")
        if isinstance(document, ErrorResult):
            result = document
        else:
            result = verify_document(
                _add_assumptions(document, assumptions),
                args.access,
                args.required,
                max_bdd_nodes=args.max_bdd_nodes,
                max_ast_nodes=args.max_ast_nodes,
            )
    elif args.command == "diff" and args.old_expr is not None:
        if args.document is not None or args.new_expr is None:
            parser.error(
                "direct comparison requires --old-expr and --new-expr without a document"
            )
        old = _parse_expression(args.old_expr, "diff", "--old-expr")
        new = _parse_expression(args.new_expr, "diff", "--new-expr")
        if isinstance(old, ErrorResult):
            result = old
        elif isinstance(new, ErrorResult):
            result = new
        else:
            result = diff(
                old,
                new,
                assumptions=assumptions,
                old_name=args.old_expr,
                new_name=args.new_expr,
                max_bdd_nodes=args.max_bdd_nodes,
                max_ast_nodes=args.max_ast_nodes,
            )
    elif args.command == "diff":
        if args.document is None or args.old is None or args.new is None:
            parser.error("named comparison requires a document, --old, and --new")
        document = _load(args.document, "diff")
        if isinstance(document, ErrorResult):
            result = document
        else:
            result = diff_document(
                _add_assumptions(document, assumptions),
                args.old,
                args.new,
                max_bdd_nodes=args.max_bdd_nodes,
                max_ast_nodes=args.max_ast_nodes,
            )
    elif args.command == "explain" and args.expr is not None:
        if args.document is not None:
            parser.error("direct explanation uses --expr without a document")
        target = _parse_expression(args.expr, "explain", "--expr")
        if isinstance(target, ErrorResult):
            result = target
        else:
            result = explain(
                target,
                assumptions=assumptions,
                target_name=args.expr,
                limit=args.limit,
                max_explanation_cubes=args.max_explanation_cubes,
                max_bdd_nodes=args.max_bdd_nodes,
                max_ast_nodes=args.max_ast_nodes,
            )
    elif args.command == "explain":
        if args.document is None or args.expression is None:
            parser.error("named explanation requires a document and --expression")
        document = _load(args.document, "explain")
        if isinstance(document, ErrorResult):
            result = document
        else:
            result = explain_document(
                _add_assumptions(document, assumptions),
                args.expression,
                limit=args.limit,
                max_explanation_cubes=args.max_explanation_cubes,
                max_bdd_nodes=args.max_bdd_nodes,
                max_ast_nodes=args.max_ast_nodes,
            )
    else:
        document = _load(args.document, "report")
        if isinstance(document, ErrorResult):
            result = document
        else:
            result = report_document(
                _add_assumptions(document, assumptions),
                limit=args.limit,
                max_explanation_cubes=args.max_explanation_cubes,
                max_bdd_nodes=args.max_bdd_nodes,
                max_ast_nodes=args.max_ast_nodes,
            )

    if args.format == "json":
        print(json.dumps(result_to_data(result), ensure_ascii=False, sort_keys=True))
    else:
        print(_text(result))
    return _exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())
