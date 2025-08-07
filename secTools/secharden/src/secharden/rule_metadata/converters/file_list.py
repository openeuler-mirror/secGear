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
from tempfile import NamedTemporaryFile
import os
from secharden.executor import CmdParameter
from secharden.rule_metadata import RuleParameter, ConfigConverter


class FileListConverter(ConfigConverter):
    """
    Converts a list of files into a temporary file that can be used in command execution.
    """

    def __init__(self):
        super().__init__()
        self._temp_file = None

    def generate(self, parameter: CmdParameter, config):
        """
        Generates a temporary file from the provided list of files and adds it to the command parameters.
        """
        if not isinstance(config, list):
            raise ValueError("file_list value must be a list")
        self._temp_file = NamedTemporaryFile("wt", delete=False, suffix=".list")
        self._temp_file.writelines([str(i) for i in config])
        self._temp_file.flush()
        parameter.add_variable("file", self._temp_file.name)

    def verify(self, parameter: RuleParameter):
        """
        Verifies that the command template contains exactly one placeholder for 'file'.
        Raises an error if the placeholder is missing or if there are multiple placeholders.
        """
        place_holder = parameter.cmd_template.variable_index
        if len(place_holder) != 1:
            raise ValueError(f"Expected exactly one placeholder, found {len(place_holder)}")
        if "file" not in place_holder:
            raise ValueError("Placeholder 'file' not found in the execute config variables")

    def cleanup(self):
        """
        Cleans up the temporary file created during the generation process.
        """
        if self._temp_file:
            try:
                self._temp_file.close()
            except Exception as e:
                logging.error(f"Error closing temp file: {e}")
            finally:
                os.remove(self._temp_file.name)
