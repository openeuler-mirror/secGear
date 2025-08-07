# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

from secharden.rule_metadata import ConfigConverter, RuleParameter
from secharden.executor import CmdParameter


class TestConverter(ConfigConverter):
    def __init__(self):
        super().__init__()
        self.temp_file = None

    def generate(self, parameter: CmdParameter, config):
        parameter.add_variable("file1", config['file1'])
        parameter.add_variable("file2", config['file2'])
        if 'env1' in config:
            parameter.add_env("env1", config['env1'])

    def verify(self, parameter: RuleParameter):
        place_holder = parameter.cmd_template.variable_index
        assert len(place_holder) == 2
        assert "file1" in place_holder
        assert "file2" in place_holder
