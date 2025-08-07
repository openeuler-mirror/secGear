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
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

import jsonschema

from secharden.exceptions import InvalidException, RuntimeException
from secharden.executor import CmdTemplate, CmdParameter, CmdExecutor
from secharden.utils import load_json_file, HOME_DIR


class RuleParameter:
    """
    Represents a rule parameter with its metadata and associated converter.
    """

    def __init__(self, parameter: Dict[str, Any]):
        """
        Initializes a RuleParameter instance.
        :param parameter: A dictionary containing the parameter metadata.
        :raises InvalidException: If the verification of the parameter fails.
        """
        self._id = parameter['id']
        self._name = parameter['name']
        self._description = parameter['description']
        converter = ConverterManager().find_converter(parameter['converter'])
        if converter is None:
            raise InvalidException(f'converter of type {parameter["converter"]} is not implemented')
        self._converter: type['ConfigConverter'] = converter
        self._cmd_template: CmdTemplate = CmdTemplate(parameter['cmd_template'])
        self._verify_rule_params()

    def _verify_rule_params(self):
        """
        Verifies the rule parameters using the associated converter.
        :raises Exception: If the verification fails.
        """
        try:
            self._converter().verify(self)
        except Exception as e:
            logging.error(f"Verification failed for parameter: {self._id}")
            raise InvalidException(e)

    @property
    def id(self) -> str:
        """
        Returns the unique identifier of the rule parameter.
        """
        return self._id

    @property
    def name(self) -> str:
        """
        Returns the name of the rule parameter.
        """
        return self._name

    @property
    def description(self) -> str:
        """
        Returns the description of the rule parameter.
        """
        return self._description

    @property
    def converter(self) -> type['ConfigConverter']:
        """
        Returns the converter class associated with this rule parameter.
        :return: The converter class.
        """
        return self._converter

    @property
    def cmd_template(self) -> CmdTemplate:
        """
        Returns the command template associated with this rule parameter.
        """
        return self._cmd_template


class ConfigConverter(abc.ABC):
    """
    Abstract base class for configuration converters.
    """

    def __init__(self):
        pass

    @abc.abstractmethod
    def generate(self, parameter: CmdParameter, config):
        """
        Generates a configuration based on the provided parameter and config.
        :param parameter: The command parameter to apply to.
        :param config: The configuration to convert.
        """
        raise NotImplementedError()

    def cleanup(self):
        """
        Cleans up any resources used by the converter, if any.
        Only triggered when the converter is generated parameter successfully.
        """
        pass

    @abc.abstractmethod
    def verify(self, parameter: RuleParameter):
        """
        Verifies the rule parameter using the converter.
        :param parameter: The rule parameter to verify.
        """
        raise NotImplementedError()


class ConverterManager:
    """
    Singleton class to manage configuration converters.
    It loads all converters from the rules.converters module and provides a method to find a converter
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self._converter: Dict[str, type[ConfigConverter]] = {}
        for cls in ConfigConverter.__subclasses__():
            self._converter[cls.__name__] = cls

    def find_converter(self, converter_type: str) -> Optional[type[ConfigConverter]]:
        """
        Finds a converter by its type name.
        :param converter_type: The type name of the converter to find.
        :return: The converter class if found, otherwise None.
        """
        return self._converter.get(converter_type, None)


class UrlDescriptor:
    """
    Represents a URL descriptor with a title and URL.
    """

    def __init__(self, **kwargs):
        """
        Initializes a UrlDescriptor instance.
        The args are not checked since they are checked using json schema.
        :param kwargs: A dictionary containing 'url' and 'title'.
        """
        self._url: str = kwargs['url']
        self._title: str = kwargs['title']

    @property
    def url(self) -> str:
        """
        Returns the URL associated with this descriptor.
        """
        return self._url

    @property
    def title(self) -> str:
        """
        Returns the title associated with this URL descriptor.
        """
        return self._title


class RuleMetadata:
    """
    Represents the metadata of a rule, parsed data from metadata.json file.
    """
    _metadata_schema = load_json_file(HOME_DIR.joinpath('schema/metadata.schema.json'))

    def __init__(self, root: Path):
        """
        Initializes a RuleMetadata instance by loading metadata from a JSON file.
        :param root: The root directory containing the metadata.json file.
        :raises InvalidException: If the metadata file is invalid or if required fields are missing.
        """
        try:
            data = load_json_file(root.joinpath("metadata.json"))
            jsonschema.validate(data, RuleMetadata._metadata_schema)
        except Exception as e:
            raise InvalidException(e)

        self._id: str = data['id']
        self._name: str = data['name']
        self._root = root
        self._description: str = data['description']
        self._entry: Path = self._parse_entry(data['entry'])
        self._parameters: List[RuleParameter] = [RuleParameter(d) for d in data.get('parameters', [])]
        self._urls: List[UrlDescriptor] = [UrlDescriptor(**u) for u in data.get('urls', [])]
        self._service: List[str] = data.get('services', [])

        if not self._entry.is_file():
            raise InvalidException(f"Entry file {self._entry} for {self._id} is not a regular file")
        if not self._id == root.name:
            raise InvalidException(f"Metadata id {self._id} does not match directory name {root.name}")

    def _parse_entry(self, entry: str) -> Path:
        # check if entry exists in root path
        if self._root.joinpath(entry).exists():
            return self._root.joinpath(entry).resolve()

        # check if entry exists in PATH
        paths = os.environ.get('PATH', '').split(':')
        for p in paths:
            path = Path(p)
            # ignore invalid paths
            if not path.is_dir() or not path.is_absolute() or not path.exists():
                continue
            entry_path = path.joinpath(entry)
            if entry_path.exists() and entry_path.is_file():
                return entry_path

        # finally raise not found error
        raise InvalidException(
            f"Entry file {entry} for {self._id} does not exist in the root path or PATH environment variable")

    def apply(self, config=None, dry_run=False):
        """
        Applies a rule with the given configuration.
        :param config: A dictionary containing configuration parameters for the rule
        :raises InvalidException: If the rule does not exist or if required parameters are missing in the configuration
        :raises RuntimeException: If the command execution fails
        """
        if config is None:
            config = {}

        # pop the 'enabled' key from config, if any
        rule = self._id
        logging.debug(f"Applying rule {rule} with config: {config}")
        executor = CmdExecutor([str(self._entry)])

        # generate command line parameters
        converter_instances = []
        for param in self._parameters:
            if param.id not in config:
                raise InvalidException(f"Parameter {param.id} is missing in the configuration for rule {rule}.")
            converter = param.converter()
            cmd_param = CmdParameter(param.cmd_template)
            try:
                converter.generate(cmd_param, config[param.id])
            except Exception as e:
                # cleanup first
                for instance in converter_instances:
                    instance.cleanup()
                logging.error(f"Failed to generate command line on parameter {param.id}.")
                raise RuntimeException(e)
            converter_instances.append(converter)
            executor.add_args(cmd_param)

        # execute the command
        try:
            if dry_run:
                logging.info(f"Dry run mode enabled. Command for rule '{rule}': {executor.cmdline}")
                return
            logging.info(f"====== Rule {rule} command execution ======")
            result = executor.run().splitlines()
            for line in result:
                logging.info(line)
        except Exception as e:
            logging.error(f"Failed to execute command for rule {rule}.")
            raise RuntimeException(e)
        finally:
            logging.info(f"====== End of rule {rule} command execution ======")
            for instance in converter_instances:
                instance.cleanup()

    @property
    def id(self) -> str:
        """
        Returns the unique identifier of the rule metadata.
        """
        return self._id

    @property
    def name(self) -> str:
        """
        Returns the name of the rule.
        """
        return self._name

    @property
    def rule_path(self) -> Path:
        """
        Returns the root path of the rule metadata.
        """
        return self._root

    @property
    def description(self) -> str:
        """
        Returns the description of the rule.
        """
        return self._description

    @property
    def entry(self) -> Path:
        """
        Returns the entry file path for the rule.
        """
        return self._entry

    @property
    def parameters(self) -> List[RuleParameter]:
        """
        Returns the list of rule parameters.
        """
        return self._parameters

    @property
    def services(self) -> List[str]:
        """
        Returns the list of services associated with the rule.
        """
        return self._service

    @property
    def urls(self) -> List[UrlDescriptor]:
        """
        Returns the list of URL descriptors associated with the rule.
        """
        return self._urls

    @property
    def doc(self) -> str:
        """
        Generates a markdown documentation string for the rule metadata.
        """
        doc = ""
        doc += f"### {self._id} {self._name}\n\n"
        doc += f"{self._description}\n\n"
        doc += f"#### 参数\n\n"
        if len(self._parameters) > 0:
            for param in self._parameters:
                doc += f"**{param.id}** {param.name}\n\n"
                doc += f"{param.description}\n\n"
        else:
            doc += "无\n\n"

        if len(self._urls) > 0:
            doc += "#### 参考文档\n\n"
            for url in self._urls:
                doc += f"- [{url.title}]({url.url})\n"
            doc += "\n"
        return doc


class CategoryMetadata:
    """
    Represents the metadata of a category, parsed data from category.json file.
    """

    def __init__(self, **kwargs):
        """
        Initializes a CategoryMetadata instance by loading metadata from a dictionary.
        :param kwargs: A dictionary containing 'id', 'name', and 'description'.
        """
        # these fields are not checked since they are checked using json schema
        self._id: str = kwargs['id']
        self._name: str = kwargs['name']
        self._description: str = kwargs['description']

    @property
    def id(self) -> str:
        """
        Returns the unique identifier of the category metadata.
        """
        return self._id

    @property
    def name(self) -> str:
        """
        Returns the name of the category.
        """
        return self._name

    @property
    def description(self) -> str:
        """
        Returns the description of the category.
        """
        return self._description

    @property
    def doc(self) -> str:
        """
        Generates a markdown documentation string for the category metadata.
        """
        doc = ""
        doc += f"## {self._id} {self._name}\n\n"
        doc += f"{self._description}\n\n"
        return doc
