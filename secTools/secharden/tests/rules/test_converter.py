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

import pytest
from pytest_mock import MockFixture

from secharden.rule_metadata import RuleMetadata
from secharden.executor import CmdParameter


class TestConverter:
    @pytest.fixture
    def config_test_path(self, request):
        return Path(request.path).parent.joinpath("metadata/param").resolve()

    def test_file_list_converter(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_single"))
        param = r.parameters[0]
        converter = param.converter()
        cmd_param = CmdParameter(param.cmd_template)
        converter.generate(cmd_param, ['test_t'])
        file = cmd_param._variables.get('file')
        assert file is not None
        assert Path(file).exists()
        assert Path(file).read_text('utf-8') == 'test_t'
        converter.cleanup()

    def test_file_list_converter_not_list(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_single"))
        param = r.parameters[0]
        converter = param.converter()
        cmd_param = CmdParameter(param.cmd_template)
        with pytest.raises(ValueError) as e:
            converter.generate(cmd_param, 'not_list')
        assert str(e.value) == "file_list value must be a list"
        converter.cleanup()

    def test_cmd_placeholders(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("cmd_placeholders"))
        param = r.parameters[0]
        converter = param.converter()
        cmd_param = CmdParameter(param.cmd_template)
        converter.generate(cmd_param, {'file1': 'test_t1', 'file2': 'test_t2', 'env1': 'test_env1'})
        assert cmd_param.cmd == ['test_t1', 'test_t2']
        assert cmd_param.env['env1'] == 'test_env1'
        converter.cleanup()

    def test_file_list_cleanup(self, config_test_path, caplog, mocker: MockFixture):
        r = RuleMetadata(config_test_path.joinpath("cmd_single"))
        param = r.parameters[0]
        converter = param.converter()
        cmd_param = CmdParameter(param.cmd_template)
        converter.generate(cmd_param, ['test_t'])

        # mock to throw an exception when closing the temp file
        klass = converter._temp_file.__class__
        module = klass.__module__
        mocker.patch(f'{module + "." + klass.__qualname__}.close',
                     side_effect=Exception("Mocked close exception"))
        with caplog.at_level(logging.ERROR):
            converter.cleanup()
        assert 'Error closing temp file:' in caplog.text