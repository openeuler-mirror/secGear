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


class TestListCmd:
    @pytest.fixture
    def rule_path(self, request):
        return Path(request.path).parent.joinpath("ruleset").resolve()

    def test_list(self, capsys, rule_path):
        assert secharden.main(["-r", str(rule_path), "list"]) == 0
        out, _ = capsys.readouterr()
        assert out == """error: Error Category
\terror.01: valid metadata
test: Test Category
\ttest.01: valid metadata
\ttest.02: valid metadata
\ttest.03: valid metadata
test1: Test1 Category
\ttest1.01: valid metadata
"""

    def test_list_category(self, capsys, rule_path):
        assert secharden.main(["-r", str(rule_path), "list", "test"]) == 0
        out, _ = capsys.readouterr()
        assert out == """test: Test Category
\ttest.01: valid metadata
\ttest.02: valid metadata
\ttest.03: valid metadata
"""

    def test_list_category_not_found(self, capsys, caplog, rule_path):
        assert secharden.main(["-r", str(rule_path), "list", "test2"]) == 1
        out, _ = capsys.readouterr()
        assert out == "Category 'test2' not found.\n"
        assert "Category 'test2' not found" in caplog.text
