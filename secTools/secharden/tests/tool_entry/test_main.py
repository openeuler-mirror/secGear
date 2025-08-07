# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

import tempfile
from pathlib import Path

import pytest

import secharden.secharden as secharden


class TestMainCmd:
    @pytest.fixture
    def rule_path(self, request):
        return Path(request.path).parent.joinpath("ruleset").resolve()

    @pytest.fixture
    def base_path(self, request):
        return Path(request.path).parent.resolve()

    def test_hint(self, capsys, rule_path):
        assert secharden.main(["-r", str(rule_path)]) == 1
        out, _ = capsys.readouterr()
        assert out == "Please specify a sub-command. Use 'secharden --help' for usage information.\n"

    def test_log_create_failed(self, capsys, base_path, rule_path):
        secharden.main(["-r", str(rule_path), "-l", str(base_path.joinpath("test_main.py"))])
        _, err = capsys.readouterr()
        assert "Error: Cannot write to log directory. Using console output instead." in err

    def test_log_create_success(self, capsys, rule_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir).joinpath("secharden_logs")
            secharden.main(["-r", str(rule_path), "-l", str(temp_path), "-d"])
            _, err = capsys.readouterr()
            assert "Error: Cannot write to log directory. Using console output instead." not in err
            # cannot assert log file here, may be pytest hijacking the logging module
            # but we can check if the temp_path exists since it should have been created by secharden
            assert temp_path.exists()
