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
import json
import logging
from logging.handlers import TimedRotatingFileHandler
import sys
from pathlib import Path

HOME_DIR = Path(__file__).parent.resolve()


class DirectoryPathVerifier(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        p = Path(values)
        if not p.exists():
            raise argparse.ArgumentTypeError(f"Directory '{values}' does not exist.")
        if not p.is_dir():
            raise argparse.ArgumentTypeError(f"'{values}' is not a directory.")
        setattr(namespace, self.dest, p)


def load_json_file(file_path: Path):
    """
    Load a JSON file from the given path.
    :param file_path: Path to the JSON file.
    :return: Parsed JSON data.
    :raises FileNotFoundError: If the file does not exist.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    return json.loads(file_path.read_text('utf-8'))


def setup_logger(log_root: Path, debug: bool = False):
    """
    Configure the logger for the application.
    :param log_root: The root directory where logs will be stored.
    :param debug: If True, set the logger to debug level; otherwise, set to info level.
    """
    logging_level = logging.INFO
    if debug:
        logging_level = logging.DEBUG
    try:
        if not log_root.exists():
            log_root.mkdir(parents=True, exist_ok=True)
        if not log_root.is_dir():
            raise ValueError(f"Log path {log_root} is not a directory.")

        handlers = [
            logging.handlers.TimedRotatingFileHandler(filename=log_root.joinpath('secharden.log'), when='D',
                                                      encoding='utf-8')
        ]
        logging.basicConfig(handlers=handlers, level=logging_level, format='%(asctime)s [%(levelname)8s] %(message)s')
    except Exception as e:
        print("Error: Cannot write to log directory. Using console output instead.", file=sys.stderr)
        logging.basicConfig(level=logging_level, format='%(asctime)s [%(levelname)8s] %(message)s', stream=sys.stderr)
        logging.exception(e)
