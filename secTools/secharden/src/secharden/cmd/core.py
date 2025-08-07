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

from secharden.cmd import Command
from secharden.rule_metadata import RuleManager
from secharden.utils import HOME_DIR


class CoreCmd(Command):
    """
    Core command for handling basic functionalities.
    """

    def __init__(self):
        super().__init__("hint", "Core command for handling basic functionalities.")

    def _add_arguments(self, parser):
        pass

    def add_parser(self, args):
        # do not add sub-command here since it is the core command
        version_file = HOME_DIR.joinpath("VERSION")
        args.add_argument('-v', '--version', action='version', version=version_file.read_text('utf-8').strip())
        args.add_argument("-r", "--rules", type=Path,
                          help="rule script directory", default=HOME_DIR.joinpath('tools'))
        args.add_argument('-l', '--logs', type=Path, help="log directory", default=Path('/var/log/secharden'))
        args.add_argument("-d", "--debug", action='store_true', help="debug mode")
        args.set_defaults(command=self)

    def _execute(self, rule_mgr: RuleManager, args):
        print("Please specify a sub-command. Use 'secharden --help' for usage information.")
        self._return_code = 1
