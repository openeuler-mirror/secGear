# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

from pathlib import Path

import pytest

import secharden.secharden as secharden
from secharden.rule_metadata import RuleManager, RuleMetadata


class TestHelpCmd:
    @pytest.fixture
    def rule_path(self, request):
        return Path(request.path).parent.joinpath("ruleset").resolve()

    def test_help_category(self, capsys, rule_path):
        assert secharden.main(["-r", str(rule_path), "help", "test"]) == 0
        out, _ = capsys.readouterr()
        r = RuleManager(rule_path)
        c = r.get_category_desc("test")
        assert out == c.doc + """test: Test Category
\ttest.01: valid metadata
\ttest.02: valid metadata
\ttest.03: valid metadata
"""

    def test_help_category_not_found(self, capsys, rule_path):
        assert secharden.main(["-r", str(rule_path), "help", "test2"]) == 1
        out, _ = capsys.readouterr()
        assert out == "'test2' not found. Use 'secharden list' to see available categories and rules.\n"

    def test_help_rule(self, capsys, rule_path):
        assert secharden.main(["-r", str(rule_path), "help", "test.01"]) == 0
        out, _ = capsys.readouterr()
        assert out == RuleMetadata(rule_path.joinpath("test.01")).doc

    def test_help_rule_not_found(self, capsys, rule_path):
        assert secharden.main(["-r", str(rule_path), "help", "notfound.02"]) == 1
        out, _ = capsys.readouterr()
        assert out == "'notfound.02' not found. Use 'secharden list' to see available categories and rules.\n"
