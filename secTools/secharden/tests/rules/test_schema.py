# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

import jsonschema
import pytest

from secharden.rule_metadata import RuleMetadata


class TestSchema:
    @pytest.fixture
    def schema(self, request):
        return RuleMetadata._metadata_schema

    def test_no_id(self, schema):
        no_id = {
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx"
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(no_id, schema)

    def test_no_name(self, schema):
        no_name = {
            "id": "xxx",
            "description": "xxx",
            "entry": "xxx"
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(no_name, schema)

    def test_no_desc(self, schema):
        no_desc = {
            "id": "xxx",
            "name": "xxx",
            "entry": "../xxx"
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(no_desc, schema)

    def test_no_entry(self, schema):
        no_entry = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(no_entry, schema)

    def test_url_no_url(self, schema):
        url_no_url = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "urls": [
                {
                    "title": "xxx"
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(url_no_url, schema)

    def test_url_no_title(self, schema):
        url_no_title = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "urls": [
                {
                    "url": "xxx"
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(url_no_title, schema)

    def test_parameter_no_id(self, schema):
        parameter_no_id = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "parameters": [
                {
                    "name": "xxx",
                    "description": "xxx",
                    "converter": "xxx",
                    "cmd_template": "xxx"
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(parameter_no_id, schema)

    def test_parameter_no_name(self, schema):
        parameter_no_name = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "parameters": [
                {
                    "id": "xxx",
                    "description": "xxx",
                    "converter": "xxx",
                    "cmd_template": "xxx"
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(parameter_no_name, schema)

    def test_parameter_no_desc(self, schema):
        parameter_no_desc = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "parameters": [
                {
                    "id": "xxx",
                    "name": "xxx",
                    "converter": "xxx",
                    "cmd_template": "xxx"
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(parameter_no_desc, schema)

    def test_parameter_no_conv(self, schema):
        parameter_no_conv = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "parameters": [
                {
                    "id": "xxx",
                    "name": "xxx",
                    "description": "xxx",
                    "cmd_template": "xxx"
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(parameter_no_conv, schema)

    def test_parameter_no_temp(self, schema):
        parameter_no_temp = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "parameters": [
                {
                    "id": "xxx",
                    "name": "xxx",
                    "description": "xxx",
                    "converter": "xxx",
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(parameter_no_temp, schema)

    def test_basic(self, schema):
        basic = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx"
        }
        jsonschema.validate(basic, schema)

    def test_full(self, schema):
        full = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "parameters": [
                {
                    "id": "xxx",
                    "name": "xxx",
                    "description": "xxx",
                    "converter": "xxx",
                    "cmd_template": "xxx"
                }
            ],
            "urls": [
                {
                    "url": "xxx",
                    "title": "xxx"
                }
            ]
        }
        jsonschema.validate(full, schema)

    def test_empty_arr(self, schema):
        empty_arr = {
            "id": "xxx",
            "name": "xxx",
            "description": "xxx",
            "entry": "xxx",
            "parameters": [
            ],
            "urls": [
            ]
        }
        jsonschema.validate(empty_arr, schema)
