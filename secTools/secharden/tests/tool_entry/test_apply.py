# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

import logging
from pathlib import Path
from subprocess import CompletedProcess

import pytest
from pytest_mock import MockerFixture

import secharden.secharden as secharden


def mock_subprocess_run(args, **_):
    # hijack restart command
    if args == ['systemctl', 'restart', 'sshd']:
        return CompletedProcess(args, 1, "Service restart failed", "Service restart failed")
    return CompletedProcess(args, 0, "", "")


class TestApplyCmd:
    @pytest.fixture
    def rule_path(self, request):
        return Path(request.path).parent.joinpath("ruleset").resolve()

    @pytest.fixture
    def base_path(self, request):
        return Path(request.path).parent.resolve()

    def test_apply_nonexistent_dir(self, capsys, rule_path):
        assert secharden.main(["-r", str(rule_path), "apply", "nonexistent_dir", "-f"]) == 1
        out, err = capsys.readouterr()
        assert "Error parsing arguments:" in err
        assert "Use 'secharden --help' for usage information.\n" == out

    def test_apply_no_config(self, capsys, caplog, rule_path):
        with caplog.at_level(logging.ERROR):
            assert secharden.main(["-r", str(rule_path), "apply", str(rule_path), "-f"]) == 1
        out, err = capsys.readouterr()
        assert f"Exception while parsing configuration from {str(rule_path)}" in caplog.text
        assert "Error parsing configuration: " in err

    def test_apply_not_dir(self, capsys, base_path, rule_path):
        assert secharden.main(["-r", str(rule_path), "apply", str(base_path.joinpath("test_main.py")), "-f"]) == 1
        out, err = capsys.readouterr()
        assert "Error parsing arguments:" in err
        assert "Use 'secharden --help' for usage information.\n" == out

    def test_apply_rule_not_found(self, capsys, caplog, base_path, rule_path):
        conf_path = str(base_path.joinpath("rule_not_found"))
        with caplog.at_level(logging.ERROR):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path, "-f"]) == 1
        out, err = capsys.readouterr()
        assert "Error: Rule 'nonexistence.01' does not exist." in err
        assert "Rule 'nonexistence.01' does not exist." in caplog.text
        assert "uncaught exception in command apply with exception InvalidException:" in caplog.text

    def test_apply_rule(self, capsys, caplog, base_path, rule_path):
        conf_path = str(base_path.joinpath("conf"))
        with caplog.at_level(logging.DEBUG):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path, "-f"]) == 0
        out, _ = capsys.readouterr()
        assert "====== Rule test.01 ======" in caplog.text
        assert "applying rule 'test.01' with configuration: {}" in caplog.text
        assert "Applying rule: test.01...ok" in out
        assert "====== End of rule test.01 ======" in caplog.text

    def test_apply_rule_dry_run(self, capsys, caplog, base_path, rule_path):
        conf_path = str(base_path.joinpath("conf"))
        with caplog.at_level(logging.DEBUG):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path, "-f", "--dry-run"]) == 0
        out, _ = capsys.readouterr()
        assert "====== Rule test.01 ======" in caplog.text
        assert "applying rule 'test.01' with configuration: {}" in caplog.text
        assert "Dry run mode enabled. Command for rule 'test.01':" in caplog.text
        assert "Applying rule: test.01...ok" in out
        assert "====== End of rule test.01 ======" in caplog.text

    def test_apply_not_enabled(self, capsys, caplog, base_path, rule_path):
        conf_path = str(base_path.joinpath("not_enable"))
        with caplog.at_level(logging.INFO):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path, "-f"]) == 0
        assert "Rule test.01 is disabled in the configuration." in caplog.text

    def test_apply_rule_invalid_conf(self, capsys, caplog, base_path, rule_path):
        conf_path = str(base_path.joinpath("invalid_conf"))
        with caplog.at_level(logging.DEBUG):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path, "-f"]) == 0
        out, _ = capsys.readouterr()
        assert "====== Rule test.02 ======" in caplog.text
        assert "applying rule 'test.02' with configuration: {}" in caplog.text
        assert "Applying rule: test.02...invalid configuration" in out
        assert "Rule 'test.02' has invalid configuration: {}" in caplog.text
        assert "====== End of rule test.02 ======" in caplog.text

    def test_apply_error_rule(self, capsys, caplog, base_path, rule_path):
        conf_path = str(base_path.joinpath("error_conf"))
        with caplog.at_level(logging.DEBUG):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path, "-f"]) == 0
        out, _ = capsys.readouterr()
        assert "====== Rule error.01 ======" in caplog.text
        assert "applying rule 'error.01' with configuration: {}" in caplog.text
        assert "Applying rule: error.01...runtime error" in out
        assert "Error applying rule 'error.01' with configuration: " in caplog.text
        assert "====== End of rule error.01 ======" in caplog.text

    def test_apply_non_root_check(self, mocker: MockerFixture, capsys, caplog, base_path, rule_path):
        # mock os.geteuid to simulate non-root user
        mocker.patch("os.geteuid", return_value=1000)
        conf_path = str(base_path.joinpath("conf"))
        with caplog.at_level(logging.DEBUG):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path]) == 1
        _, err = capsys.readouterr()
        assert ("Error: This command requires root privileges. Please run as root or use --force to bypass this check."
                in err)
        assert "This command requires root privileges." in caplog.text

    def test_apply_root_check(self, mocker: MockerFixture, capsys, caplog, base_path, rule_path):
        mocker.patch("os.geteuid", return_value=0)
        conf_path = str(base_path.joinpath("conf"))
        with caplog.at_level(logging.DEBUG):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path]) == 0
        out, _ = capsys.readouterr()
        assert "====== Rule test.01 ======" in caplog.text
        assert "applying rule 'test.01' with configuration: {}" in caplog.text
        assert "Applying rule: test.01...ok" in out
        assert "====== End of rule test.01 ======" in caplog.text

    def test_service_restart(self, mocker: MockerFixture, capsys, caplog, base_path, rule_path):
        mocker.patch("secharden.executor.CmdExecutor.run", return_value="")
        conf_path = str(base_path.joinpath("service"))
        with caplog.at_level(logging.DEBUG):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path, "-f"]) == 0
        out, _ = capsys.readouterr()
        assert "====== Rule test.03 ======" in caplog.text
        assert "applying rule 'test.03' with configuration: {}" in caplog.text
        assert "Applying rule: test.03...ok" in out
        assert "====== End of rule test.03 ======" in caplog.text
        assert "Restarting service: sshd...ok" in out

    def test_service_restart_failed(self, mocker: MockerFixture, capsys, caplog, base_path, rule_path):
        mocker.patch("subprocess.run", side_effect=mock_subprocess_run)
        conf_path = str(base_path.joinpath("service"))
        with caplog.at_level(logging.DEBUG):
            assert secharden.main(["-r", str(rule_path), "apply", conf_path, "-f"]) == 0
        out, err = capsys.readouterr()
        assert "====== Rule test.03 ======" in caplog.text
        assert "applying rule 'test.03' with configuration: {}" in caplog.text
        assert "Applying rule: test.03...ok" in out
        assert "====== End of rule test.03 ======" in caplog.text
        assert "Restarting service: sshd...failed" in out
        assert "Error restarting service 'sshd'" in caplog.text
        assert "Error restarting service 'sshd'" in err
