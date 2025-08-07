# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
# http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

import argparse
import logging
import sys

from secharden.cmd import CoreCmd, ApplyCmd, ListCmd, HelpCmd
from secharden.rule_metadata import RuleManager
from secharden.utils import setup_logger


def main(argv=None):
    args = argparse.ArgumentParser(prog="secharden")

    # base args
    CoreCmd().add_parser(args)

    subparser = args.add_subparsers(help="sub-commands")
    commands = [
        # apply rule configs
        ApplyCmd(),
        # list rules
        ListCmd(),
        # rule help messages
        HelpCmd()
    ]

    for cmd in commands:
        cmd.add_parser(subparser)

    try:
        args = args.parse_args(argv)
    except argparse.ArgumentTypeError as e:
        print(f"Error parsing arguments: {e}", file=sys.stderr)
        print("Use 'secharden --help' for usage information.")
        return 1

    # setup logging
    setup_logger(args.logs, args.debug)

    logging.info(f"start secharden: {args.command.name}")

    # init rule manager after logging are set up
    return args.command.execute(RuleManager(args.rules), args)
