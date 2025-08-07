# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

from secharden.cmd import Command
from secharden.cmd.list import list_rules
from secharden.rule_metadata import RuleManager


class HelpCmd(Command):
    def __init__(self):
        super().__init__("help", "Show help doc for rule or category")

    def _add_arguments(self, parser):
        parser.add_argument("rule", nargs=1, help="rule or category id to show help for")

    def _execute(self, rule_mgr: RuleManager, args):
        """
        Execute the help command to show documentation for a specific rule or category.
        :param rule_mgr: RuleManager instance to access rules and categories.
        :param args: Parsed arguments containing the rule or category to show help for.
        """
        rule = args.rule[0]

        if rule_mgr.category_exists(rule):
            print(rule_mgr.get_category_desc(rule).doc, end='')
            self._return_code = list_rules(rule_mgr, rule)
            return

        if rule_mgr.rule_exists(rule):
            print(rule_mgr.get_rule_metadata(rule).doc, end='')
            return

        print(f"'{rule}' not found. Use 'secharden list' to see available categories and rules.")
        self._return_code = 1
