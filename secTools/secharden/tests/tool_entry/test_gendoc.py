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
import shutil
import tempfile
from pathlib import Path

import pytest

import secharden.devtools.gendoc as gendoc


class TestMainCmd:
    @pytest.fixture
    def rule_path(self, request):
        return Path(request.path).parent.joinpath("ruleset").resolve()

    @pytest.fixture
    def base_path(self, request):
        return Path(request.path).parent.resolve()

    def test_wrong_rule_path(self, caplog, base_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            with caplog.at_level(logging.ERROR):
                result = gendoc.main(["-r", temp_dir])
        assert result == 1
        assert "Error generating documentation:" in caplog.text

    def test_gendoc(self, caplog, rule_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            shutil.copytree(rule_path, temp_dir, dirs_exist_ok=True)
            with caplog.at_level(logging.INFO):
                result = gendoc.main(["-r", temp_dir, '-d'])
            assert result == 0
            assert "Generating doc for rule: test.01" in caplog.text
            assert "Generating doc for rule: test1.01" in caplog.text
            # doc content already tested
            assert Path(temp_dir).joinpath('README.md').exists()

    def test_gendoc_no_force(self, caplog, rule_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            shutil.copytree(rule_path, temp_dir, dirs_exist_ok=True)
            result = gendoc.main(["-r", temp_dir])
            assert result == 0
            with caplog.at_level(logging.ERROR):
                result = gendoc.main(["-r", temp_dir])
            assert result == 1
            assert f"File {Path(temp_dir).joinpath('README.md')} already exists" in caplog.text
            assert "Error generating documentation:" in caplog.text

    def test_gendoc_force(self, caplog, rule_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            shutil.copytree(rule_path, temp_dir, dirs_exist_ok=True)
            result = gendoc.main(["-r", temp_dir])
            assert result == 0
            caplog.set_level(logging.INFO)
            result = gendoc.main(["-r", temp_dir, "-f"])
            assert result == 0
            assert "force to generate doc, deleting existing doc files" in caplog.text
