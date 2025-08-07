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
from typing import Optional

from secharden.cmd import Command
from secharden.rule_metadata import RuleManager


def list_rules(rule_mgr: RuleManager, category: Optional[str] = None) -> int:
    """
    List available rules in the specified category or all categories.
    If a category is specified, it will list rules only in that category.
    If no category is specified, it will list rules in all categories.
    :param rule_mgr: RuleManager instance to manage rules
    :param category: Category to list rules for
    :return: 0 if successful, 1 if the category does not exist
    """
    categories = [category] if category else rule_mgr.categories
    if category and not rule_mgr.category_exists(category):
        logging.error(f"Category '{category}' not found.")
        print(f"Category '{category}' not found.")
        return 1

    for category_id in categories:
        category = rule_mgr.get_category_desc(category_id)
        print(f"{category_id}: {category.name}")
        rules = rule_mgr.get_rules_by_category(category_id)
        for rule in rules:
            metadata = rule_mgr.get_rule_metadata(rule)
            print(f"\t{rule}: {metadata.name}")
    return 0


class ListCmd(Command):
    def __init__(self):
        super().__init__("list", "List available rules")

    def _add_arguments(self, parser):
        parser.add_argument("category", nargs='?', help="category of rule to list")

    def _execute(self, rule_mgr: RuleManager, args):
        self._return_code = list_rules(rule_mgr, args.category)
