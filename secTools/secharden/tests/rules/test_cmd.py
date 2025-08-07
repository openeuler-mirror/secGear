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

from secharden.rule_metadata import RuleMetadata
from secharden.executor import CmdParameter


class TestCmdParam:
    @pytest.fixture
    def config_test_path(self, request):
        return Path(request.path).parent.joinpath("metadata/param").resolve()

    def test_cmd_multi_placeholder(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_multi_placeholder"))
        param = CmdParameter(r.parameters[0].cmd_template)
        param.add_variable('file', 'cmd_multi_placeholder')
        assert param.cmd == ['cmd_multi_placeholder', 'cmd_multi_placeholder']

    def test_cmd_escape(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_escape"))
        param = CmdParameter(r.parameters[0].cmd_template)
        param.add_variable('file', 'cmd_escape')
        assert param.cmd == ['cmd_escape', '%file']

    def test_cmd_single(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_single"))
        param = CmdParameter(r.parameters[0].cmd_template)
        param.add_variable('file', 'cmd_single')
        assert param.cmd == ['cmd_single', 'test']

    def test_cmd_no_variable(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_single"))
        param = CmdParameter(r.parameters[0].cmd_template)
        with pytest.raises(ValueError) as e:
            c = param.cmd
        assert str(e.value) == "Variable file not found in variable collection"

    def test_cmd_placeholders(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_placeholders"))
        param = CmdParameter(r.parameters[0].cmd_template)
        param.add_variable('file1', 'cmd_placeholders1')
        param.add_variable('file2', 'cmd_placeholders2')
        # unused variable is ignored
        param.add_variable('file3', 'cmd_placeholders3')
        assert param.cmd == ['cmd_placeholders1', 'cmd_placeholders2']

    def test_cmd_env(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_single"))
        param = CmdParameter(r.parameters[0].cmd_template)
        param.add_variable('file', 'cmd_env')
        param.add_env('cmd_env', 'test1')
        assert param.env['cmd_env'] == 'test1'
