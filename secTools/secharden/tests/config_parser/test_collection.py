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

from secharden.config_parser import collect_configs
from secharden.exceptions import InvalidException


class TestConfigCollector:
    @pytest.fixture
    def config_test_path(self, request):
        return Path(request.path).parent.joinpath("collection").resolve()

    def test_empty(self, config_test_path):
        with pytest.raises(InvalidException):
            collect_configs(config_test_path.joinpath("empty"))

    def test_single_file(self, config_test_path):
        p = collect_configs(config_test_path.joinpath("single_file"))
        assert len(p) == 1
        assert p[0].name == "secharden.conf"

    def test_collection_only(self, config_test_path):
        with pytest.raises(InvalidException):
            collect_configs(config_test_path.joinpath("only_collection"))

    def test_full_collection(self, config_test_path):
        p = collect_configs(config_test_path.joinpath("full_collection"))
        assert len(p) == 3
        assert p[0].name == "secharden.conf"
        # reversed, the 01 will override 02
        assert p[1].name == "02-test2.conf"
        assert p[2].name == "01-test.conf"

    def test_collection_wrong_name(self, config_test_path):
        p = collect_configs(config_test_path.joinpath("collection_wrong_name"))
        assert len(p) == 1
        assert p[0].name == "secharden.conf"
