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

from secharden.exceptions import InvalidException, RuntimeException
from secharden.rule_metadata import RuleMetadata


class TestMetadata:
    @pytest.fixture
    def config_test_path(self, request):
        return Path(request.path).parent.joinpath("metadata").resolve()

    def test_valid(self, config_test_path):
        path = config_test_path.joinpath("valid")
        d = RuleMetadata(path)
        assert d.id == 'valid'
        assert d.name == 'valid metadata'
        assert d.description == 'valid metadata'
        assert d.entry == path.joinpath("metadata.json")
        assert d.rule_path == path

    def test_entry_in_path(self, config_test_path):
        path = config_test_path.joinpath("entry_in_path")
        d = RuleMetadata(path)
        assert d.id == 'entry_in_path'
        assert d.name == 'valid metadata'
        assert d.description == 'valid metadata'

        # search python
        import os
        paths = os.environ.get('PATH', '').split(':')
        paths.insert(0, "invalid_path")
        for p in paths:
            path = Path(p)
            # ignore invalid paths
            if not path.is_dir() or not path.is_absolute() or not path.exists():
                continue
            entry_path = path.joinpath('python3')
            if entry_path.exists() and entry_path.is_file():
                assert d.entry == entry_path
                break

    def test_valid_full(self, config_test_path):
        path = config_test_path.joinpath("valid_full")
        d = RuleMetadata(path)
        assert d.id == 'valid_full'
        assert d.name == 'valid metadata'
        assert d.description == 'valid metadata'
        assert d.entry == path.joinpath("metadata.json")
        assert len(d.parameters) == 1
        param = d.parameters[0]
        assert param.id == 'xxx'
        assert param.name == 'xxx'
        assert param.description == 'xxx'
        assert param.converter.__name__ == 'FileListConverter'
        assert param.cmd_template.template == ['%file', 'test']
        assert param.cmd_template.variable_index == {'file': [0]}
        urls = d.urls
        assert len(urls) == 1
        assert urls[0].url == 'https://example.com'
        assert urls[0].title == 'example'

    def test_entry_not_file(self, config_test_path):
        path = config_test_path.joinpath("entry_not_file")
        with pytest.raises(InvalidException) as excinfo:
            RuleMetadata(path)
        assert str(excinfo.value) == f"Entry file {path.resolve()} for entry_not_file is not a regular file"

    def test_no_entry(self, config_test_path):
        path = config_test_path.joinpath("no_entry")
        with pytest.raises(InvalidException) as excinfo:
            RuleMetadata(path)
        assert (str(excinfo.value) ==
                f"Entry file no_entry.sh for no_entry does not exist in the root path or PATH environment variable")

    def test_no_metadata(self, config_test_path):
        path = config_test_path.joinpath("no_metadata")
        with pytest.raises(InvalidException) as excinfo:
            RuleMetadata(path)
        assert str(excinfo.value) == f"File not found: {path.joinpath('metadata.json')}"

    def test_directory_name_mismatch(self, config_test_path):
        dirname = "directory_name_mismatch"
        with pytest.raises(InvalidException) as excinfo:
            RuleMetadata(config_test_path.joinpath(dirname))
        assert str(excinfo.value) == f"Metadata id valid does not match directory name {dirname}"

    def test_rule_apply_rule(self, config_test_path, caplog):
        r = RuleMetadata(config_test_path.joinpath("normal_exec").resolve())
        caplog.set_level(logging.DEBUG)
        r.apply()
        assert "Applying rule normal_exec with config: {}" in caplog.text
        assert "====== Rule normal_exec command execution ======" in caplog.text
        assert "hello from entry.sh" in caplog.text
        assert "====== End of rule normal_exec command execution ======" in caplog.text

    def test_rule_apply_rule_fail(self, config_test_path, caplog):
        r = RuleMetadata(config_test_path.joinpath("fail_exec").resolve())

        caplog.set_level(logging.INFO)
        with pytest.raises(RuntimeException):
            r.apply()
        assert "====== Rule fail_exec command execution ======" in caplog.text
        assert "Failed to execute command for rule fail_exec." in caplog.text
        assert "====== End of rule fail_exec command execution ======" in caplog.text

    def test_rule_apply_rule_miss_param(self, config_test_path):
        r = RuleMetadata(config_test_path.joinpath("exec_with_param").resolve())
        with pytest.raises(InvalidException) as e:
            r.apply()
        assert str(e.value) == "Parameter input is missing in the configuration for rule exec_with_param."

    def test_rule_apply_rule_invalid_param(self, config_test_path, caplog):
        r = RuleMetadata(config_test_path.joinpath("exec_with_param").resolve())

        caplog.set_level(logging.ERROR)
        with pytest.raises(RuntimeException):
            assert r.apply({'input': {'file1': 'file1.txt'}})
        assert "Failed to generate command line on parameter input." in caplog.text

    def test_rule_apply_rule_with_param(self, config_test_path, caplog):
        r = RuleMetadata(config_test_path.joinpath("exec_with_param").resolve())

        config = {'input': {'file1': 'file1.txt', 'file2': 'file2.txt'}}
        caplog.set_level(logging.DEBUG)
        r.apply(config)
        assert f"Applying rule exec_with_param with config: {config}" in caplog.text
        assert "====== Rule exec_with_param command execution ======" in caplog.text
        assert "hello file1.txt file2.txt" in caplog.text
        assert "====== End of rule exec_with_param command execution ======" in caplog.text

    # def test_rule_manager_apply_rule_invalid_param_second(self, config_test_path, caplog):
    #     execution = config_test_path.joinpath("execution").resolve()
    #     manager = RuleManager(execution)
    #
    #     config = {
    #         'input': {'file1': 'file1.txt', 'file2': 'file2.txt'},
    #         'input1': {'file1': 'file1.txt'}
    #     }
    #
    #     caplog.set_level(logging.ERROR)
    #     assert not manager.apply_rule("test.04", config)
    #     assert "Failed to generate command line on parameter input1." in caplog.text

    def test_valid_full_doc(self, config_test_path):
        path = config_test_path.joinpath("valid_full")
        assert RuleMetadata(path).doc == """### valid_full valid metadata

valid metadata

#### 参数

**xxx** xxx

xxx

#### 参考文档

- [example](https://example.com)

"""

    def test_valid_doc(self, config_test_path):
        path = config_test_path.joinpath("valid")
        assert RuleMetadata(path).doc == """### valid valid metadata

valid metadata

#### 参数

无

"""
