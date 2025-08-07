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


class InvalidException(Exception):
    """Invalid data exception."""

    def __init__(self, message=None):
        if message is None:
            message = "Invalid Exception"
        super().__init__(message)
        logging.exception(message)


class RuntimeException(Exception):
    """Runtime error exception."""

    def __init__(self, message=None):
        if message is None:
            message = "Runtime Exception"
        super().__init__(message)
        logging.exception(message)
