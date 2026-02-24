# Nornir-Detect

A Nornir plugin for automatic network device detection using the [device-detect](https://pypi.org/project/device-detect/) module.

## Features

- 🔍 **Automatic Device Detection**: Detects device types using SNMP and/or SSH
- 🔧 **Auto-Configuration**: Automatically updates Nornir host platform and connection options
- 📦 **Data Collection**: Collects device data for offline analysis and debugging
- 🎯 **Multi-Protocol**: Supports SNMP (v1, v2c, v3) and SSH detection methods
- 🔌 **Connection Plugin Support**: Configures netmiko, scrapli, napalm, and puresnmp
- 📊 **Framework Mapping**: Provides driver mappings for multiple automation frameworks

## Installation

### Basic Installation (Core Only)

```bash
pip install nornir-detect
```

### With Optional Dependencies

```bash
# Install with all connection plugins
pip install nornir-detect[full]

# Install with specific plugins
pip install nornir-detect[netmiko,utils]
pip install nornir-detect[scrapli,napalm]
```

### Available Extras

- `netmiko` - nornir-netmiko plugin
- `scrapli` - nornir-scrapli plugin
- `napalm` - nornir-napalm plugin
- `salt` - nornir-salt plugin (for puresnmp)
- `ansible` - nornir-ansible plugin
- `utils` - nornir-utils plugin
- `full` - All of the above

## Quick Start

### 1. Configure Inventory

Create your inventory with credentials:

```yaml
# hosts.yaml
router1:
  hostname: 192.168.1.1

# defaults.yaml
username: admin
password: secret123
port: 22
data:
  # SNMP credentials
  snmp_community: public
  snmp_version: 2
  
  # Or SNMPv3
  snmp_version: 3
  snmp_user: snmpuser
  snmp_auth_password: authpass
  snmp_priv_password: privpass
  snmp_auth_proto: sha1
  snmp_priv_proto: aes
```

### 2. Detect Device Types

```python
from nornir import InitNornir
from nornir_detect import detect

# Initialize Nornir
nr = InitNornir(inventory="inventory.yaml")

# Run detection
result = nr.run(task=detect)

# Access results
for host, task_result in result.items():
    detection = task_result.result
    print(f"{host}: {detection.device_type} (score: {detection.score})")
```

### 3. Use Detected Platforms

After detection, the host's platform and connection options are automatically configured:

```python
from nornir_netmiko import netmiko_send_command

# Platform is now set, you can use connection plugins directly
result = nr.run(
    task=netmiko_send_command,
    command_string="show version"
)
```

## Usage

### Detection Task

The `detect` task identifies device types and automatically configures connection options.

```python
from nornir_detect import detect

result = nr.run(
    task=detect,
    enable_snmp=True,              # Enable SNMP detection
    ssh_verification=False,        # Verify SNMP results via SSH
    ssh_version_filter=True,       # Filter by SSH version
    ssh_version_fallback=True,     # Test all types if no match
    ssh_timing_profile="normal",   # SSH timing: fast/normal/slow
    update_platform=True,          # Auto-update connection options
    log_level="INFO"               # Logging level
)
```

**Result contains:**
- `device_type`: Detected device type (e.g., 'cisco_ios')
- `score`: Confidence score (0-100)
- `method`: Detection method used ('SNMP', 'SSH', 'SNMP+SSH')
- `nornir_driver`: Netmiko driver name
- `scrapli_driver`: Scrapli platform name
- `napalm_driver`: NAPALM driver name
- `timing`: Detection timing information

### Collection Task

The `collect` task gathers device data without detection for offline analysis.

```python
from nornir_detect import collect

result = nr.run(
    task=collect,
    snmp_only=False,               # Collect only SNMP data
    ssh_only=False,                # Collect only SSH data
    collect_ssh_commands=True,     # Collect SSH command outputs
    additional_commands=[          # Additional commands to collect
        "show interfaces",
        "show ip route"
    ],
    sanitize_output=False,         # Remove escape characters
    save_to_file=True,             # Save to file
    output_path="data/{host}.json", # Custom path ({host} = hostname)
    output_format='json'           # Format: json/csv/excel/yaml
)
```

**Data is saved to:** `collected_data/{hostname}.json` by default

### Connection Options Helpers

Configure connection options manually if needed:

```python
from nornir_detect import (
    set_connection_options_netmiko,
    set_connection_options_scrapli,
    set_connection_options_napalm,
    set_connection_options_puresnmp,
    set_connection_options  # Configures netmiko, scrapli, napalm
)

# Set individual connection options
nr.run(task=set_connection_options_netmiko)

# Or set all at once (netmiko + scrapli + napalm)
nr.run(task=set_connection_options)
```

## Supported Device Types

The plugin supports all device types recognized by the device-detect module, including:

- Cisco IOS, IOS-XE, IOS-XR, NX-OS, ASA
- Aruba AOS-CX, ArubaOS-Switch (ProCurve)
- HP Comware
- OneAccess OneOS
- And more...

## Advanced Examples

### Detection with SSH Verification

```python
# Use SNMP for initial detection, then verify via SSH
result = nr.run(
    task=detect,
    enable_snmp=True,
    ssh_verification=True  # Verify SNMP result via SSH
)
```

### Collect Data with Custom Commands

```python
result = nr.run(
    task=collect,
    collect_ssh_commands=True,
    additional_commands=[
        "show running-config",
        "show interfaces status",
        "show ip arp"
    ],
    output_path="backups/{host}_data.json"
)
```

### Error Handling

```python
result = nr.run(task=detect)

for host, task_result in result.items():
    if task_result.failed:
        print(f"{host} failed: {task_result.exception}")
    else:
        detection = task_result.result
        print(f"{host}: {detection.device_type}")
```

## API Reference

### Tasks

#### `detect(task, **kwargs)`
Detect device type and auto-configure connection options.

**Parameters:**
- `enable_snmp` (bool): Enable SNMP detection (default: True)
- `ssh_verification` (bool): Verify SNMP via SSH (default: False)
- `ssh_version_filter` (bool): Filter by SSH version (default: True)
- `ssh_version_fallback` (bool): Fallback to all types (default: True)
- `ssh_timing_profile` (str): Timing profile (default: 'normal')
- `update_platform` (bool): Update host platform (default: True)
- `log_level` (str): Logging level (default: 'INFO')

#### `collect(task, **kwargs)`
Collect device data for offline analysis.

**Parameters:**
- `snmp_only` (bool): Collect only SNMP (default: False)
- `ssh_only` (bool): Collect only SSH (default: False)
- `collect_ssh_commands` (bool): Collect SSH commands (default: False)
- `additional_commands` (list): Extra commands (default: None)
- `sanitize_output` (bool): Clean output (default: False)
- `save_to_file` (bool): Save to file (default: True)
- `output_path` (str): File path (default: 'collected_data/{host}.json')
- `output_format` (str): Format (default: 'json')

### Helpers

- `set_connection_options_netmiko(task)` - Configure netmiko
- `set_connection_options_scrapli(task)` - Configure scrapli
- `set_connection_options_napalm(task)` - Configure napalm
- `set_connection_options_puresnmp(task)` - Configure puresnmp
- `set_connection_options(task)` - Configure all (netmiko + scrapli + napalm)

## Requirements

- Python >= 3.7
- nornir >= 3.0.0
- device-detect >= 0.7.0

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Mohamed RABAH**
- Email: mdrbh0@gmail.com
- GitHub: [@mdrbh0](https://github.com/mdrbh0)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

This plugin leverages the [device-detect](https://pypi.org/project/device-detect/) module for device identification.
