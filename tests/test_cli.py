"""Tests for the CLI entry point."""

import json

from policy_validator.cli import main


class TestCLIText:
    def test_insecure_file_exits_1(self, insecure_config_file):
        rc = main([str(insecure_config_file)])
        assert rc == 1

    def test_secure_file_exits_0(self, secure_config_file):
        rc = main([str(secure_config_file)])
        assert rc == 0

    def test_missing_file_exits_2(self, tmp_path):
        rc = main([str(tmp_path / "nope.json")])
        assert rc == 2

    def test_fail_on_critical_only_passes_high(self, tmp_path):
        cfg = tmp_path / "c.json"
        cfg.write_text('{"debug": true}')  # HIGH, not CRITICAL
        rc = main([str(cfg), "--fail-on", "CRITICAL"])
        assert rc == 0

    def test_fail_on_never_always_passes(self, insecure_config_file):
        rc = main([str(insecure_config_file), "--fail-on", "never"])
        assert rc == 0

    def test_min_severity_filters_output(self, secure_config_file, capsys):
        main([str(secure_config_file), "--min-severity", "CRITICAL", "--fail-on", "never"])
        out = capsys.readouterr().out
        # INFO-level findings should be suppressed
        assert "SEC-009" not in out

    def test_multiple_files(self, insecure_config_file, secure_config_file):
        rc = main([str(insecure_config_file), str(secure_config_file)])
        assert rc == 1  # insecure file should trigger failure


class TestCLIJson:
    def test_json_output_structure(self, insecure_config_file, capsys):
        main([str(insecure_config_file), "--format", "json", "--fail-on", "never"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "findings" in data
        assert "summary" in data
        assert "errors" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0

    def test_json_findings_have_required_fields(self, insecure_config_file, capsys):
        main([str(insecure_config_file), "--format", "json", "--fail-on", "never"])
        data = json.loads(capsys.readouterr().out)
        for finding in data["findings"]:
            assert "rule_id" in finding
            assert "severity" in finding
            assert "message" in finding
            assert "field" in finding

    def test_json_error_on_missing_file(self, tmp_path, capsys):
        main([str(tmp_path / "missing.json"), "--format", "json"])
        data = json.loads(capsys.readouterr().out)
        assert len(data["errors"]) > 0

    def test_json_secure_config_no_blocking_findings(self, secure_config_file, capsys):
        main([str(secure_config_file), "--format", "json", "--fail-on", "never"])
        data = json.loads(capsys.readouterr().out)
        blocking = [f for f in data["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
        assert blocking == []
