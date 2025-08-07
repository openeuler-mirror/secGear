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

from secharden.exceptions import InvalidException
from secharden.rule_metadata import RuleMetadata


class TestMetadataParam:
    @pytest.fixture
    def config_test_path(self, request):
        return Path(request.path).parent.joinpath("metadata/param").resolve()

    def test_cmd_mismatch_id(self, config_test_path):
        with pytest.raises(InvalidException) as excinfo:
            RuleMetadata(config_test_path.joinpath("cmd_mismatch_id"))
        assert str(excinfo.value) == "Placeholder 'file' not found in the execute config variables"

    def test_cmd_multi_placeholder(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_multi_placeholder"))
        assert r.parameters[0].id == 'xxx'
        assert r.parameters[0].name == 'xxx'
        assert r.parameters[0].description == 'xxx'
        assert r.parameters[0].converter.__name__ == 'FileListConverter'
        assert r.parameters[0].cmd_template.template == ['%file', '%file']
        assert r.parameters[0].cmd_template.variable_index == {'file': [0, 1]}

    def test_cmd_no_placeholder(self, config_test_path):
        with pytest.raises(InvalidException) as excinfo:
            RuleMetadata(config_test_path.joinpath("cmd_no_placeholder"))
        assert str(excinfo.value) == "Expected exactly one placeholder, found 0"

    def test_cmd_noid(self, config_test_path):
        with pytest.raises(InvalidException) as excinfo:
            RuleMetadata(config_test_path.joinpath("cmd_noid"))
        assert str(excinfo.value) == "invalid cmd template with no id"

    def test_no_converter(self, config_test_path):
        with pytest.raises(InvalidException) as excinfo:
            RuleMetadata(config_test_path.joinpath("no_converter"))
        assert str(excinfo.value) == 'converter of type NotFoundConverter is not implemented'

    def test_cmd_escape(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_escape"))
        assert r.parameters[0].id == 'xxx'
        assert r.parameters[0].name == 'xxx'
        assert r.parameters[0].description == 'xxx'
        assert r.parameters[0].converter.__name__ == 'FileListConverter'
        assert r.parameters[0].cmd_template.template == ['%file', '%file']
        assert r.parameters[0].cmd_template.variable_index == {'file': [0]}

    def test_cmd_single(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_single"))
        assert r.parameters[0].id == 'xxx'
        assert r.parameters[0].name == 'xxx'
        assert r.parameters[0].description == 'xxx'
        assert r.parameters[0].converter.__name__ == 'FileListConverter'
        assert r.parameters[0].cmd_template.template == ['%file', 'test']
        assert r.parameters[0].cmd_template.variable_index == {'file': [0]}

    def test_cmd_placeholders(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_placeholders"))
        assert r.parameters[0].id == 'xxx'
        assert r.parameters[0].name == 'xxx'
        assert r.parameters[0].description == 'xxx'
        assert r.parameters[0].converter.__name__ == 'TestConverter'
        assert r.parameters[0].cmd_template.template == ['%file1', '%file2']
        assert r.parameters[0].cmd_template.variable_index == {'file1': [0], 'file2': [1]}
