# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

import abc
import logging
from typing import final

from secharden.rule_metadata import RuleManager


class Command(abc.ABC):
    def __init__(self, name: str, description: str):
        self._name = name
        self._description = description
        self._return_code = 0

    @abc.abstractmethod
    def _execute(self, rule_mgr: RuleManager, args):
        """
        Execute the command with the given arguments.
        :param rule_mgr: An instance of RuleManager to manage rules.
        :param args: Arguments for the command.
        """
        raise NotImplementedError()

    @final
    def execute(self, rule_mgr: RuleManager, args) -> int:
        """
        Execute the command and return the result.
        :param rule_mgr: An instance of RuleManager to manage rules.
        :param args: Arguments for the command.
        :return: The result of the command execution.
        """
        try:
            self._execute(rule_mgr, args)
        except Exception as e:
            logging.fatal(f"uncaught exception in command {self._name} with exception {type(e).__name__}:")
            logging.exception(e)
            if self._return_code == 0:
                self._return_code = 1
        return self._return_code

    @abc.abstractmethod
    def _add_arguments(self, parser):
        """
        Add common arguments to the parser.
        :param parser: The parser to which common arguments will be added.
        """
        raise NotImplementedError()

    def add_parser(self, subparser):
        """
        Add command-specific arguments to the parser.
        :param subparser: The subparser to which command-specific arguments will be added.
        """
        command_parser = subparser.add_parser(self._name, help=self._description)
        self._add_arguments(command_parser)
        command_parser.set_defaults(command=self)

    @property
    def name(self) -> str:
        """
        Get the name of the command.
        :return: The name of the command.
        """
        return self._name
