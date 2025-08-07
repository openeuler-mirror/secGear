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
from typing import List, Dict, Any

import jsonschema

from secharden.exceptions import InvalidException
from secharden.rule_metadata import RuleMetadata
from secharden.rule_metadata.metadata import CategoryMetadata
from secharden.utils import load_json_file, HOME_DIR


def precheck(rule_path: Path) -> bool:
    """
    Pre-checks for a rule directory to ensure it meets the expected structure and naming conventions.
    :param rule_path: Path to the rule directory
    :return: True if the rule directory is valid, False otherwise
    """
    if not rule_path.is_dir():
        logging.error(f"Rule path {rule_path} is not a directory")
        return False
    if not rule_path.name.split('.', 1)[1].isdigit():
        logging.error(
            f"Rule directory {rule_path.name} does not have a valid numeric index after the category")
        return False
    if int(rule_path.name.split('.', 1)[1]) <= 0:
        logging.error(f"Rule directory {rule_path.name} has an invalid index (must be > 0)")
        return False
    if not rule_path.joinpath("metadata.json").is_file():
        logging.error(f"Rule path {rule_path} does not contain a metadata.json file")
        return False
    return True


class RuleManager:
    """
    RuleManager is responsible for managing rules and categories in a specified directory.
    """

    def __init__(self, rules_dir: Path):
        """
        Initializes the RuleManager with the specified rule directory.
        :param rules_dir: Path to the directory containing rule files
        :raises FileNotFoundError: If the rules directory does not exist
        :raises NotADirectoryError: If the specified path is not a directory
        :raises ValueError: If the rules directory does not contain a valid categories.json file
        :raises jsonschema.ValidationError: If the categories.json file does not conform to the schema
        """
        self._dir = rules_dir.resolve()
        self._rules: List[str] = []
        self._categories: List[str] = []

        if not self._dir.exists():
            logging.error(f"Rules directory does not exist: {self._dir}")
            return
        if not self._dir.is_dir():
            logging.error(f"Path is not a directory: {self._dir}")
            return
        self.reload_rules()

    @property
    def path(self) -> Path:
        """ Returns the path to the rule base directory. """
        return self._dir

    @property
    def categories(self) -> List[str]:
        """ Returns a copy of the category information. """
        return self._categories.copy()

    @property
    def rules(self) -> List[str]:
        """ Returns a copy of the list of rules. """
        return self._rules.copy()

    def rule_exists(self, rule_id: str) -> bool:
        """
        Checks if a rule with the given ID exists in the manager.
        :param rule_id: The ID of the rule to check
        :return: True if the rule exists, False otherwise
        """
        return rule_id in self._rules

    def category_exists(self, category_id: str) -> bool:
        """
        Checks if a category with the given ID exists in the manager.
        :param category_id: The ID of the category to check
        :return: True if the category exists, False otherwise
        """
        return category_id in self._categories

    def get_rules_by_category(self, category_id: str) -> List[str]:
        """
        Retrieves all rules associated with a specific category ID.
        :param category_id: The ID of the category to retrieve rules for
        :return: A list of rule IDs associated with the specified category
        :raises ValueError: If the category ID does not exist in the manager
        """
        if category_id not in self._categories:
            raise ValueError(f"Category with ID {category_id} not found")
        return [rule for rule in self._rules if rule.startswith(category_id + '.')]

    def get_rule_metadata(self, rule_id: str) -> RuleMetadata:
        """
        Retrieves the metadata for a specific rule by its ID.
        :param rule_id: The ID of the rule to retrieve metadata for
        :return: An instance of RuleMetadata containing the rule's metadata
        :raises ValueError: If the rule ID does not exist in the manager
        """
        if rule_id not in self._rules:
            raise ValueError(f"Rule with ID {rule_id} not found")
        rule = self._dir.joinpath(rule_id).resolve()
        return RuleMetadata(rule)

    def get_category_desc(self, category_id: str) -> CategoryMetadata:
        """
        Retrieves the description of a specific category by its ID.
        :param category_id: The ID of the category to retrieve
        :return: A dictionary containing the category's description and metadata
        :raises ValueError: If the category ID does not exist in the manager
        """
        if category_id not in self._categories:
            raise ValueError(f"Category with ID {category_id} not found")
        return CategoryMetadata(id=category_id, **load_json_file(self._dir.joinpath('categories.json'))[category_id])

    def reload_rules(self):
        """
        Reloads the rules and categories from the rules directory.
        This method reads the categories.json file and validates it against the schema.
        It then collects all valid rules for each category and stores them in the manager.
        :raises InvalidException: If the categories.json file not found or does not conform to the schema
        :raises ValueError: If the rules directory does not contain a valid categories.json file
        """
        try:
            categories: Dict[str, Dict[str, Any]] = load_json_file(self._dir.joinpath('categories.json'))
            jsonschema.validate(categories, load_json_file(HOME_DIR.joinpath('schema/categories.schema.json')))
        except Exception as e:
            raise InvalidException(e)

        # id is verified by jsonschema
        for category_id in sorted(categories.keys()):
            # collect all valid rules
            rules: List[str] = []
            for rule_path in self._dir.glob(f"{category_id}.*"):
                if not precheck(rule_path):
                    logging.warning(f"Skipping invalid rule path: {rule_path}")
                    continue
                try:
                    RuleMetadata(rule_path)
                    rules.append(rule_path.name)
                except InvalidException:
                    logging.error(f"Rule dir {rule_path} is not valid")

            if len(rules) == 0:
                logging.error(f"No rules found for category {category_id}")
                continue

            self._categories.append(category_id)
            self._rules.extend(sorted(rules, key=lambda r: int(r.split('.', 1)[1])))
