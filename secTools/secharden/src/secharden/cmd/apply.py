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
import os
import sys
from pathlib import Path

from secharden.cmd import Command
from secharden.config_parser import collect_configs, parse_config
from secharden.exceptions import InvalidException, RuntimeException
from secharden.executor import CmdExecutor
from secharden.rule_metadata import RuleManager
from secharden.utils import DirectoryPathVerifier


class ApplyCmd(Command):
    def __init__(self):
        super().__init__('apply', 'Apply security rules from configuration files')
        self._service_collector = set()

    def _add_arguments(self, parser):
        parser.add_argument('config', nargs='?', action=DirectoryPathVerifier, help="configuration path",
                            default=Path('/etc/secharden'))
        parser.add_argument('-f', '--force', action='store_true',
                            help="force apply rules without checking root privileges")
        parser.add_argument("--dry-run", action='store_true', help="dry run mode, do not execute commands")

    def _apply_rule(self, rule: str, rule_conf: dict, rule_mgr: RuleManager, args):
        """
        Apply a single rule with its configuration.
        Returns True if the rule was applied successfully, False otherwise.
        """
        if not rule_mgr.rule_exists(rule):
            print(f"Error: Rule '{rule}' does not exist.", file=sys.stderr)
            logging.error(f"Rule '{rule}' does not exist.")
            raise InvalidException(f"Rule '{rule}' does not exist.")

        if not rule_conf.pop('enabled', True):
            logging.info(f"Rule {rule} is disabled in the configuration.")
            return

        metadata = rule_mgr.get_rule_metadata(rule)
        print(f"Applying rule: {rule}...", end='', flush=True)

        logging.info(f"====== Rule {rule} ======")
        logging.debug(f"applying rule '{rule}' with configuration: {rule_conf}")
        try:
            metadata.apply(rule_conf, dry_run=args.dry_run)
            print('ok')

            # record services that need to be restarted
            self._service_collector.update(metadata.services)
        except InvalidException:
            print('invalid configuration')
            logging.error(f"Rule '{rule}' has invalid configuration: {rule_conf}")
        except RuntimeException:
            print('runtime error')
            logging.error(f"Error applying rule '{rule}' with configuration: {rule_conf}")
        finally:
            logging.info(f"====== End of rule {rule} ======")

    def _execute(self, rule_mgr: RuleManager, args):
        if not args.force and not os.geteuid() == 0:
            print(
                "Error: This command requires root privileges. Please run as root or use --force to bypass this check.",
                file=sys.stderr)
            logging.error("This command requires root privileges.")
            self._return_code = 1
            return

        try:
            config = parse_config(collect_configs(args.config))
        except InvalidException as e:
            logging.error(f"Exception while parsing configuration from {args.config}")
            print(f"Error parsing configuration: {e}", file=sys.stderr)
            self._return_code = 1
            return

        for rule, rule_conf in config.items():
            if rule_conf is None:
                rule_conf = {}
            self._apply_rule(rule, rule_conf, rule_mgr, args)

        # restart services if any rules were applied
        for service in self._service_collector:
            print(f"Restarting service: {service}...", end='', flush=True)
            try:
                if not args.dry_run:
                    executor = CmdExecutor(['systemctl', 'restart', service])
                    executor.run()
                print('ok')
            except RuntimeException as e:
                print('failed')
                logging.error(f"Error restarting service '{service}': {e}")
                print(f"Error restarting service '{service}': {e}", file=sys.stderr)
