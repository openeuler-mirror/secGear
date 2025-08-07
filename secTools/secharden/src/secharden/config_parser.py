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
from typing import Dict, List, Any

import yaml
import jsonschema

from secharden.exceptions import InvalidException

# just limit to dict is enough
CHECK_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "id": "./categories.schema.json",
    "title": "Tool categories metadata Schema",
    "description": "Schema file for tool categories specification",
    "allOf": [{"type": "object"}]
}


def verify_config_name(path: Path) -> bool:
    name = path.name
    if not '-' in name:
        logging.error(f"Config {path} does not follow naming convention (should be 'priority-config_name')")
        return False
    if not name.split('-', 1)[0].isdigit():
        logging.error(f"Config {path} does not have a valid priority index")
        return False
    if int(name.split('-', 1)[0]) <= 0:
        logging.error(f"Config {path} has a priority index less than or equal to zero")
        return False
    return True


def collect_configs(config_dir: Path) -> List[Path]:
    """
    Collects all configuration files from the specified directory.
    It looks for a main config file and additional config files in a subdirectory.
    :param config_dir: Path to the directory containing configuration files.
    :return: A list of Paths to the configuration files.
    :raises InvalidException: If the main config file is not found.
    """
    file_collection: List[Path] = []

    baseline = config_dir.joinpath("secharden.conf")
    if not baseline.exists():
        raise InvalidException(f"Config file is not found in {config_dir}")
    file_collection.append(baseline)

    user_config = config_dir.joinpath("secharden.conf.d")
    if user_config.exists() and user_config.is_dir():
        configs: List[Path] = list(user_config.glob(f"*.conf"))
        file_collection.extend(
            sorted(filter(verify_config_name, configs), key=lambda r: int(r.name.split('-', 1)[0]), reverse=True))

    return file_collection


def parse_config(configs: List[Path]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for file in configs:
        logging.debug(f"Parsing config file: {file}")
        try:
            yaml_data = yaml.safe_load(file.read_text('utf-8'))
            jsonschema.validate(yaml_data, CHECK_SCHEMA)
        except Exception as e:
            logging.error(f"Error parsing YAML file {file}: {e}")
            continue
        result.update(yaml_data)
    if len(result) == 0:
        logging.error(f"No valid configuration found in the provided files: {configs}")
        raise InvalidException("No valid configuration found in the provided files.")
    return result
