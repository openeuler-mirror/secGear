# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

import pytest

from secharden.exceptions import RuntimeException
from secharden.executor import CmdExecutor, CmdTemplate, CmdParameter


class TestExecutor:

    def test_normal(self):
        c = CmdExecutor(['echo'])
        template = CmdTemplate('name')
        param = CmdParameter(template)
        c.add_args(param)
        assert c.run() == 'name\n'

    def test_error(self):
        c = CmdExecutor(['ls'])
        template = CmdTemplate('/nonexistent_directory')
        param = CmdParameter(template)
        c.add_args(param)
        with pytest.raises(RuntimeException):
            c.run()
