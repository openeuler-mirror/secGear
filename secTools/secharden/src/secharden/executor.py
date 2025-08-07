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
from typing import Dict, List

from secharden.exceptions import InvalidException, RuntimeException


class CmdTemplate:
    """
    A class to parse a command template and extract variable indexes.
    """

    def __init__(self, template: str):
        """
        Initializes the CmdTemplate with a command template string.
        The template can contain variables prefixed with % and escaped variables with %%.
        :param template: The command template string.
        :raises InvalidException: If the template is invalid (e.g., contains a variable with no id).
        """
        self._template = template.split(' ')
        self._variable_index: Dict[str, List[int]] = self._parse_cmd_template()

    def _parse_cmd_template(self) -> Dict[str, List[int]]:
        escape_indexes = []
        variable_index: Dict[str, List[int]] = {}
        for i, cmd in enumerate(self._template):
            if cmd.startswith('%%'):
                escape_indexes.append(i)
                continue
            if cmd.startswith('%'):
                variable_id = cmd[1:]
                if len(variable_id) == 0:
                    raise InvalidException('invalid cmd template with no id')
                if variable_id in variable_index:
                    variable_index[variable_id].append(i)
                else:
                    variable_index[variable_id] = [i]
        for i in escape_indexes:
            # remove prefix escaping char % in %%
            self._template[i] = self._template[i][1:]
        return variable_index

    @property
    def template(self) -> List[str]:
        """
        Returns the command template as a list of strings.
        """
        # make a copy so that other modules can modify the template without affecting the original
        return self._template.copy()

    @property
    def variable_index(self) -> Dict[str, List[int]]:
        """
        Returns the variable index mapping variable ids to their positions in the command template.
        """
        return self._variable_index


class CmdParameter:
    """
    A class to hold command parameters and environment variables.
    It uses a CmdTemplate to manage command templates and allows adding variables and environment variables.
    """

    def __init__(self, template: CmdTemplate):
        """
        Initializes the CmdParameter with a CmdTemplate.
        """
        self._cmd_template = template
        self._variables = {}
        self._env = {}

    def add_variable(self, variable_id: str, value: str):
        """
        Adds a variable to the command parameters.
        If the variable already exists, it will be overwritten.
        :param variable_id: The identifier for the variable (without the % prefix).
        :param value: The value of the variable.
        :raises ValueError: If the variable_id is empty.
        """
        self._variables[variable_id] = value

    def add_env(self, name: str, value: str):
        """
        Adds an environment variable to the command parameters.
        If the variable already exists, it will be overwritten.
        :param name: The name of the environment variable.
        :param value: The value of the environment variable.
        :raises ValueError: If the name is empty.
        """
        self._env[name] = value

    @property
    def cmd(self) -> List[str]:
        """
        Returns the command as a list of strings, with variables replaced by their values.
        If a variable is not found in the variable collection, it raises a ValueError.
        :raises ValueError: If a variable is not found in the variable collection.
        :return: The command with variables replaced.
        """
        result = self._cmd_template.template
        for var_id, index in self._cmd_template.variable_index.items():
            value = self._variables.get(var_id)
            if value is None:
                logging.error(f"Variable {var_id} not found in variable collection")
                raise ValueError(f"Variable {var_id} not found in variable collection")
            for i in index:
                result[i] = value
        return result

    @property
    def env(self) -> Dict[str, str]:
        """
        Returns the environment variables as a dictionary.
        """
        return self._env


class CmdExecutor:
    """
    A class to execute commands using a command template and parameters.
    It allows adding arguments and environment variables, and runs the command in a subprocess.
    """

    def __init__(self, entry: List[str]):
        """
        Initializes the CmdExecutor with a command entry point.
        :param entry: The path to the command entry point.
        """
        self._cmd = entry.copy()
        self._env = {}

    @property
    def cmdline(self) -> List[str]:
        """
        Returns the command line as a list of strings.
        This includes the command entry point and any added arguments.
        """
        return self._cmd.copy()

    def add_args(self, args: CmdParameter):
        """
        Adds command arguments and environment variables to the executor.
        :param args: A CmdParameter instance containing command arguments and environment variables.
        """
        self._cmd.extend(args.cmd)
        self._env.update(args.env)

    def run(self):
        """
        Executes the command with the provided arguments and environment variables.
        It captures the output and returns it.
        :raises RuntimeError: If the command execution fails.
        :return: The output of the command execution.
        """
        import subprocess
        import os

        env = os.environ.copy()
        env.update(self._env)

        result = subprocess.run(self._cmd, env=env, capture_output=True, text=True)

        if result.returncode != 0:
            logging.error(f"Command execution failed with return code {result.returncode}")
            logging.error(f"Command stdout: {result.stdout}")
            err = result.stderr
            logging.error(f"Command stderr: {err}")
            raise RuntimeException(f"Command failed with error: {err}")

        return result.stdout
