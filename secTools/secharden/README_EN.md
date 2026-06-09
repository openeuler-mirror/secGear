# secharden

## Overview

secharden is a Python-based system hardening framework used to manage and apply various security hardening rules.
It provides a flexible way to enhance system security and supports the configuration and execution of multiple hardening rules.

## Installation

Install secharden using pip:

```bash
python3 -m pip install .
```

## Usage

The secharden command provides multiple functions, including applying hardening rules, printing the hardening rule list, and viewing the help information about rules.

### Applying Hardening Rules

secharden reads the configuration file and applies the corresponding hardening rules.

If no rule path is specified, the default `/etc/secharden` directory is used.

```bash
secharden apply
```

If you need to specify a rule path, add it after `secharden apply`:

```bash
secharden apply [/path/to/config_path]
```

secharden outputs the applied rules. The following is an example:

```plaintext
Applying rule: int.01...
```

#### Configuration File Directory

**Configuration File Directory Structure**

The specified rule path must be a directory, which must contain a basic configuration file `secharden.conf`.

You can also create a `secharden.conf.d` directory and place multiple configuration files in this directory. The tool will automatically load these configuration files. The configuration files in this directory must meet the following requirements:

- The configuration file is named in the format of `<Priority>-<Name>.conf`, for example, `01-disable_ptrace.conf`. `<Priority>`
  is an integer greater than 0, indicating the loading priority of the configuration file. A smaller value indicates a higher priority.

**Configuration File Format**

The configuration file is in YAML format and contains a dictionary with the rule ID as the key and parameters with the value as the rules. Example:

```yaml
int.01:
  enabled: true
int.03:
  selinux_tags:
    - user_home_t
    - var_log_t
net.01:
  enabled: false
net.02:
```

The preceding configuration file indicates that the `int.01`, `int.03`, and `net.02` rules are enabled, the `net.01` rule is explicitly disabled, and the SELinux label is specified for the `int.03` rule.

Each rule has a special `enabled` parameter that is used to enable or disable the rule. By default, all rules are enabled. You can disable a rule by setting
`enabled: false`. The following is an example:

```yaml
int.01:
  enabled: false
```

### Printing the Hardening Rule List

You can run the `secharden list` command to print the list of currently loaded hardening rules. This command lists all available rules. You can also pass parameters to view the list of rules of a specified type.

```bash
secharden list [Type ID]
```

Result example:

```plaintext
int: full-stack integrity
        int.01: Enable the kernel module signature.
        int.02: Enable the DIM dynamic measurement kernel.
        int.03: Enable IMA to measure key files.
kern: kernel hardening
        kern.01: Enable BPF hardening.
        kern.02: Enable the kernel ASLR.
        kern.03: Ensure that the kernel exits directly after an error is triggered.
```

### Viewing Rule Help Information

Parameters can be passed to view the help information for a specified type or rule. By supplying either a rule ID or a type ID, you can access the corresponding help details.

```bash
secharden help <Rule ID or type ID>
```

Result example:

```plaintext
### int.01: Enable the kernel module signature.

Enable the kernel module signature. The kernel module signature adds signature information to the end of the kernel module file in a certain format. When the system loads the kernel module, it checks whether the signature matches the public key preset in the kernel. This verifies the authenticity and integrity of the kernel module file and prevents the system from loading unauthenticated malicious kernel modules.

#### Parameters

None

```

### Common Command Parameters

The following command parameters are applicable to all secharden commands. These commands must be used after the `secharden` command. The following is an example:

```bash
secharden --rules /path/to/rules apply /path/to/config_path
```

#### Version Information

Print the current secharden version information.

```bash
secharden --version
```

#### Specifying the Rule Path

To specify the rule path, use the `--rules` or `-r` parameter. The default value is the `tools` directory.

```bash
secharden --rules /path/to/rules
```

> Note: The specified rule path must be a directory, which must contain the `categories.json` file that describes rule categories. Each rule directory must meet the following requirements:
> 
> - Each rule directory must contain a `metadata.json` file that describes the rule details.
> - The rule directory is named in the format of <Type>.<No.>, for example, `system.01` and `network.02`. The type must be the same as that in the `categories.json` file.
> - The `metadata.json` file in the rule directory must comply with the `schema/metadata.json` specifications in the tool directory.

The tool verifies the rule directories in the current rule path. If any directory does not meet the requirements, it will not be loaded to the tool rule list.
If a custom rule path is used, you are advised to run the following command to check whether the rule path is loaded to the list:

```bash
secharden -r /path/to/rules list
```

If the requirements are not met, query the error information in the log file of the tool.

#### Specifying the Log Path

To specify a log path, use the `--log` or `-l` parameter. The default value is `/var/log/secharden`.

```bash
secharden --log /path/to/log_directory
```

> Note: The specified log path must be a directory.

#### Enabling the Debug Mode

To enable the debug mode, use the `--debug` or `-d` parameter.

```bash
secharden --debug
```

After this mode is enabled, the tool outputs more debugging information in the log file to help users locate faults.
