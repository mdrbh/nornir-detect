"""
Nornir Device Detect Plugin

A Nornir plugin that leverages the device-detect module for automatic
network device type detection and data collection.

Provides:
- detect: Detect device type and auto-configure connection options
- collect: Collect device data for offline analysis
- Connection option helpers for netmiko, scrapli, napalm, puresnmp
"""

from nornir_detect.tasks import detect, collect
from nornir_detect.helpers import (
    set_connection_options_puresnmp,
    set_connection_options_netmiko,
    set_connection_options_scrapli,
    set_connection_options_napalm,
    set_connection_options
)

__version__ = "0.1.2"
__all__ = [
    "detect",
    "collect",
    "set_connection_options_puresnmp",
    "set_connection_options_netmiko",
    "set_connection_options_scrapli",
    "set_connection_options_napalm",
    "set_connection_options",
]
