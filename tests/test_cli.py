import json
from importlib.metadata import version
from pathlib import Path

import pytest

from authz_analyzer.cli import main

ROOT = Path(__file__).parent.parent


def test_version(capsys):
    with pytest.raises(SystemExit) as stopped:
        main(["--version"])

    assert stopped.value.code == 0
    assert capsys.readouterr().out == f"authz {version('authz-analyzer')}\n"


def test_validate_json(capsys):
    code = main(["validate", str(ROOT / "examples/pii-access.json"), "--format=json"])

    assert code == 0
    assert json.loads(capsys.readouterr().out) == {
        "kind": "validate",
        "resultVersion": "1",
        "status": "valid",
    }


def test_verify_text_reports_a_counterexample(capsys):
    code = main(
        [
            "verify",
            str(ROOT / "examples/pii-access.json"),
            "--access=user.ssn",
        ]
    )

    output = capsys.readouterr().out
    assert code == 1
    assert "VIOLATED: access 'user.ssn' does not imply requirement 'user.ssn'" in output
    assert "SUPPORT_OVERRIDE=true" in output
    assert "INCIDENT_OPEN=true" in output


def test_diff_json_reports_widening_and_diagnostics(capsys):
    code = main(
        [
            "diff",
            str(ROOT / "examples/policy-diff.json"),
            "--old=old",
            "--new=new",
            "--format=json",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert code == 1
    assert result["classification"] == "widened"
    assert result["addedAccess"]["counterexample"]["complete"] is True
    assert result["diagnostics"]["variableOrder"] == [
        "EMPLOYEE",
        "PII_READ",
        "SUPPORT_OVERRIDE",
        "INCIDENT_OPEN",
    ]


def test_explain_json_reports_complete_minimal_family_with_metadata(capsys):
    code = main(
        [
            "explain",
            str(ROOT / "examples/pii-access.json"),
            "--expression=user.ssn",
            "--format=json",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["truncated"] is False
    assert len(result["explanations"]) == 3
    assert result["explanations"][0]["literals"][0]["atom"] == "ADMIN"
    assert result["explanations"][0]["literals"][0]["metadata"]["category"] == "role"


def test_report_returns_failure_for_any_violated_requirement(capsys):
    code = main(
        [
            "report",
            str(ROOT / "examples/pii-access.json"),
            "--format=json",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert code == 1
    assert result["kind"] == "report"
    assert result["entries"][0]["status"] == "violated"
    assert len(result["entries"][0]["explanations"]) == 2


def test_direct_expression_commands(capsys):
    verify_code = main(
        [
            "verify",
            "--access-expr=a",
            "--required-expr=b",
            "--assume=a -> b",
            "--format=json",
        ]
    )
    verification = json.loads(capsys.readouterr().out)

    diff_code = main(["diff", "--old-expr=a", "--new-expr=a | b", "--format=json"])
    difference = json.loads(capsys.readouterr().out)

    explain_code = main(["explain", "--expr=a | !b", "--format=json"])
    explanation = json.loads(capsys.readouterr().out)

    assert verify_code == 0
    assert verification["status"] == "holds"
    assert verification["activeAssumptions"] == 1
    assert diff_code == 1
    assert difference["classification"] == "widened"
    assert explain_code == 0
    assert explanation["explanations"] == [
        {
            "minimality": "subset-minimal",
            "literals": [{"atom": "a", "value": True}],
        },
        {
            "minimality": "subset-minimal",
            "literals": [{"atom": "b", "value": False}],
        },
    ]


def test_cli_assumptions_extend_document_assumptions(capsys):
    code = main(
        [
            "verify",
            str(ROOT / "examples/pii-access.json"),
            "--access=user.ssn",
            "--assume=SUPPORT_OVERRIDE -> PII_READ",
            "--format=json",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["status"] == "holds"
    assert result["activeAssumptions"] == 2


def test_invalid_direct_expression_uses_error_result(capsys):
    code = main(
        [
            "explain",
            "--expr=a &",
            "--format=json",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["error"]["code"] == "invalid_syntax"
    assert result["error"]["details"]["argument"] == "--expr"


def test_invalid_document_uses_error_exit_code(tmp_path, capsys):
    document = tmp_path / "invalid.json"
    document.write_text("{not json")

    code = main(["validate", str(document), "--format=json"])

    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["status"] == "invalid_input"
    assert result["error"]["code"] == "invalid_json"
    assert result["error"]["line"] == 1


def test_unknown_name_uses_error_exit_code(capsys):
    code = main(
        [
            "verify",
            str(ROOT / "examples/pii-access.json"),
            "--access=missing",
        ]
    )

    assert code == 2
    assert "unknown_expression" in capsys.readouterr().out


def test_cli_applies_ast_limit(capsys):
    code = main(
        [
            "verify",
            str(ROOT / "examples/pii-access.json"),
            "--access=user.ssn",
            "--max-ast-nodes=1",
            "--format=json",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["status"] == "resource_limit"
    assert result["error"]["code"] == "ast_node_limit"
