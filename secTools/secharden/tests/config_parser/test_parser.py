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

from secharden.config_parser import parse_config
from secharden.exceptions import InvalidException


class TestConfigParser:
    @pytest.fixture
    def config_test_path(self, request):
        return Path(request.path).parent.joinpath("parser").resolve()

    def test_single_file(self, config_test_path):
        d = parse_config([config_test_path.joinpath("single_file/secharden.conf")])
        assert d == {'int.01': None, 'int.03': None, 'selinux_tags': ['ima_t', 'ima2_t']}

    def test_wrong_file(self, config_test_path):
        with pytest.raises(InvalidException):
            parse_config([config_test_path.joinpath("wrong_file/secharden.conf")])

    def test_invalid_yaml(self, config_test_path):
        with pytest.raises(InvalidException):
            parse_config([config_test_path.joinpath("invalid_yaml/secharden.conf")])

    def test_wrong_file_in_collection(self, config_test_path):
        d = parse_config([
            config_test_path.joinpath("wrong_file_in_collection/1.conf"),
            config_test_path.joinpath("wrong_file_in_collection/2.conf"),
        ])
        assert d == {'int.01': {'enabled': False}}

    def test_override(self, config_test_path):
        d = parse_config([
            config_test_path.joinpath("override/1.conf"),
            config_test_path.joinpath("override/2.conf"),
        ])
        assert d == {'int.01': {'enabled': True}}

        d = parse_config([
            config_test_path.joinpath("override/2.conf"),
            config_test_path.joinpath("override/1.conf"),
        ])
        assert d == {'int.01': {'enabled': False}}

    def test_intersect(self, config_test_path):
        d = parse_config([
            config_test_path.joinpath("intersect/1.conf"),
            config_test_path.joinpath("intersect/2.conf"),
        ])
        assert d == {'int.01': {'enabled': False}, 'int.02': {'enabled': True}}
