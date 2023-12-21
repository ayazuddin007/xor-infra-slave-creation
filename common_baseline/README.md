Role Name
=========

common_baseline

This role installs and configures the baseline software packages which are required for any newly created Linux vm based on Debian and Redhat distribution.Current role install following components:

1. Falcon sensor
2. Qualys Agent
3. Datadog Agent
4. Chrony
5. AWS Cli
6. Miscellanous : Git,Htop,tree,curl (this list can be extended)

The implementation of the role is done taking one main task playbook and including playbook for each different component such as Falcon sensor, Qualys agent, Datadog Agent, chrony and AWS CLI.Each component is having conditional execution based on variables.The base package installation task is included main playbook as this is required on each newly created vm.

Requirements
------------

Ansible 2.6 or later.

Role Variables
--------------

**install_falcon:** (Boolean) -  Determines whether to install the falcon sensor.

**falcon_package_deb:** (String) - Name of Falcon Sensor package file for Debian distribution.

**falcon_copy_path_deb:** (String) - The temporary destination path for copy of package on Debian based distribution for Falcon Sensor

**falcon_copy_path_redhat:** (String) The temporary destination path for copy of package on Redhat based distribution for Falcon Sensor

**falcon_cid:** (String) -  The checksum for Customer ID of installion file.

**falcon_config_deb:** (String) The configuration file path for Falcon sensor on Debian based distribution

**falcon_service_name:** (String)

**install_qualys:** (Boolean) -  Determines whether to install qualys agent.

**qualys_aid:** (String) - Activation ID for qualys agent

**qualys_cid:** (String) - Customer ID for qualys agent

**qualys_agent_script:** (String) Path for qualys agent installation script.

**qualys_copy_path_deb:** (String) The temporary destination path for copy of package on Debian based distribution for qualys Agent

**qualys_copy_path_redhat:** (String) The temporary destination path for copy of package on Debian based distribution for qualys Agent

**install_chrony:** (Boolean) -  Determines whether to install the chrony service.

**install_datadog_agent:** (Boolean) -  Determines whether to install the datadog agent.

**ubuntu_apt_key:** (String) -  The apt key for autenticating deb packages

**datadog_version:** (String) - Supported values: a supported version number, or blank for the latest version.

**datadog_api_key:** (String) -  The api key for datadog agent installation.

**base_packages:** (list) list of base packages needed for every vm instance.

**awscli_target_version:** (String) - Supported values: a supported version number, or blank for the latest version.

**awscli_install_path:** (list) The installation path for awscli installtion and configuration file.

**set_timezone:** (String) Default value is "Etc/UTC".

Dependencies
------------

None.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - setup_baseline
