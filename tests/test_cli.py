import json
import shutil
from pathlib import Path

from click.testing import CliRunner

from secops_triage.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def copy_fixtures(dst: Path) -> Path:
    for name in ("conn.log", "dns.log", "ssl.log"):
        shutil.copy(FIXTURES / name, dst / name)
    return dst


def test_parse_json_counts_each_indicator(tmp_path):
    result = CliRunner().invoke(main, ["parse", str(copy_fixtures(tmp_path)), "--json"])
    assert result.exit_code == 0, result.output
    rows = {(r["value"], r["source"]): r["count"] for r in json.loads(result.stdout)}
    assert rows[("93.184.216.34", "conn.log")] == 2
    assert rows[("example.com", "dns.log")] == 2
    assert rows[("2001:db8::1", "conn.log")] == 1


def test_parse_reports_skipped_lines_on_stderr_not_stdout(tmp_path):
    result = CliRunner().invoke(main, ["parse", str(copy_fixtures(tmp_path)), "--json"])
    assert "skipped 2" in result.stderr
    json.loads(result.stdout)  # stdout stays pure JSON, safe to pipe into jq


def test_parse_top_limits_output(tmp_path):
    result = CliRunner().invoke(
        main, ["parse", str(copy_fixtures(tmp_path)), "--json", "--top", "2"]
    )
    assert len(json.loads(result.stdout)) == 2


def test_parse_rejects_a_missing_directory(tmp_path):
    result = CliRunner().invoke(main, ["parse", str(tmp_path / "nope")])
    assert result.exit_code != 0


def test_table_prints_log_values_literally_not_as_markup(tmp_path):
    (tmp_path / "dns.log").write_text('{"query": "[bold]untrusted.example"}\n')
    result = CliRunner().invoke(main, ["parse", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "[bold]untrusted.example" in result.stdout


def test_parse_type_filter_keeps_only_that_type(tmp_path):
    result = CliRunner().invoke(
        main, ["parse", str(copy_fixtures(tmp_path)), "--json", "--type", "domain"]
    )
    assert result.exit_code == 0, result.output
    rows = json.loads(result.stdout)
    assert rows
    assert all(r["type"] == "domain" for r in rows)


def test_parse_type_filter_rejects_unknown_types(tmp_path):
    result = CliRunner().invoke(main, ["parse", str(tmp_path), "--type", "url"])
    assert result.exit_code == 2
