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

from secharden.exceptions import InvalidException
from secharden.rule_metadata.manager import RuleManager, precheck


class TestRuleManager:
    @pytest.fixture
    def rule_path(self, request):
        return Path(request.path).parent.joinpath("ruleset").resolve()

    def test_precheck_not_dir(self, rule_path, caplog):
        naming = rule_path.joinpath("naming")

        not_dir = naming.joinpath("notdir.01").resolve()
        with caplog.at_level(logging.ERROR):
            assert not precheck(not_dir)
        assert f"Rule path {not_dir} is not a directory" in caplog.text

    def test_precheck_not_digit(self, rule_path, caplog):
        naming = rule_path.joinpath("naming")

        not_digit = naming.joinpath("test.o3").resolve()
        with caplog.at_level(logging.ERROR):
            assert not precheck(not_digit)
        assert f"Rule directory {not_digit.name} does not have a valid numeric index after the category" in caplog.text

    def test_precheck_not_positive(self, rule_path, caplog):
        naming = rule_path.joinpath("naming")

        not_positive = naming.joinpath("test.00").resolve()
        with caplog.at_level(logging.ERROR):
            assert not precheck(not_positive)
        assert f"Rule directory {not_positive.name} has an invalid index (must be > 0)" in caplog.text

    def test_precheck_no_metadata(self, rule_path, caplog):
        naming = rule_path.joinpath("naming")

        no_metadata = naming.joinpath("nometa.01").resolve()
        with caplog.at_level(logging.ERROR):
            assert not precheck(no_metadata)
        assert f"Rule path {no_metadata} does not contain a metadata.json file" in caplog.text

    def test_rule_manager_not_dir(self, rule_path, caplog):
        with caplog.at_level(logging.ERROR):
            r = RuleManager(rule_path.joinpath("not_a_dir"))
        assert f"Path is not a directory: {rule_path.joinpath('not_a_dir').resolve()}" in caplog.text
        assert len(r.rules) == 0

    def test_rule_manager_not_found(self, rule_path, caplog):
        with caplog.at_level(logging.ERROR):
            r = RuleManager(rule_path.joinpath("non_existent_dir"))
        assert f"Rules directory does not exist: {rule_path.joinpath('non_existent_dir').resolve()}" in caplog.text
        assert len(r.rules) == 0

    def test_rule_manager_no_categories(self, rule_path):
        no_cat = rule_path.joinpath("no_categories").resolve()
        with pytest.raises(InvalidException) as e:
            RuleManager(no_cat)
        assert str(e.value) == f"File not found: {no_cat.joinpath('categories.json')}"

    def test_rule_manager_init(self, rule_path, caplog):
        naming = rule_path.joinpath("naming").resolve()
        caplog.set_level(logging.WARNING)
        manager = RuleManager(naming)
        assert f"Rule dir {naming.joinpath('invalid.01')} is not valid" in caplog.text
        assert f"No rules found for category nometa" in caplog.text
        assert f"No rules found for category notdir" in caplog.text
        assert f"No rules found for category invalid" in caplog.text

        assert manager.path == naming
        assert manager.categories == ["test", "test1"]
        assert manager.rules == ["test.01", "test1.01"]

    def test_rule_manager_rule_exists(self, rule_path):
        naming = rule_path.joinpath("naming").resolve()
        manager = RuleManager(naming)

        assert manager.rule_exists("test.01")
        assert not manager.rule_exists("nonexistent.01")

    def test_rule_manager_category_exists(self, rule_path):
        naming = rule_path.joinpath("naming").resolve()
        manager = RuleManager(naming)

        assert manager.category_exists("test")
        assert not manager.category_exists("nonexistent")

    def test_rule_manager_get_rules_by_category(self, rule_path):
        naming = rule_path.joinpath("naming").resolve()
        manager = RuleManager(naming)

        assert manager.get_rules_by_category("test") == ["test.01"]
        assert manager.get_rules_by_category("test1") == ["test1.01"]
        with pytest.raises(ValueError) as e:
            manager.get_rules_by_category("nonexistent")
        assert str(e.value) == "Category with ID nonexistent not found"

    def test_rule_manager_get_rule_metadata(self, rule_path):
        naming = rule_path.joinpath("naming").resolve()
        manager = RuleManager(naming)

        metadata = manager.get_rule_metadata("test.01")
        assert metadata.id == "test.01"
        assert metadata.name == "valid metadata"
        assert metadata.description == "valid metadata"
        assert metadata.entry == naming.joinpath("test.01").joinpath("metadata.json").resolve()

        with pytest.raises(ValueError) as e:
            manager.get_rule_metadata("nonexistent.01")
        assert str(e.value) == "Rule with ID nonexistent.01 not found"

        with pytest.raises(ValueError) as e:
            manager.get_rule_metadata("nometa.01")
        assert str(e.value) == "Rule with ID nometa.01 not found"

    def test_rule_manager_get_category_desc(self, rule_path):
        naming = rule_path.joinpath("naming").resolve()
        manager = RuleManager(naming)

        desc = manager.get_category_desc("test")
        assert desc.id == "test"
        assert desc.name == "Test Category"
        assert desc.description == "This is a test category with metadata."

        with pytest.raises(ValueError) as e:
            manager.get_category_desc("nonexistent")
        assert str(e.value) == "Category with ID nonexistent not found"

    def test_category_doc(self, rule_path):
        naming = rule_path.joinpath("naming")
        manager = RuleManager(naming)
        assert manager.get_category_desc("test").doc == """## test Test Category

This is a test category with metadata.

"""
