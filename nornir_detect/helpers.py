"""
Helper functions for configuring Nornir connection options.

These functions update the host connection options for various connection
plugins based on detected device types and inventory data.
"""

import logging
from nornir.core.inventory import ConnectionOptions
from nornir.core.task import Task

logger = logging.getLogger(__name__)


def set_connection_options_puresnmp(task: Task) -> None:
    """
    Set puresnmp connection options from SNMP credentials in inventory.
    
    Reads SNMP configuration from task.host.data and configures the
    puresnmp connection plugin.
    
    Args:
        task: Nornir Task object
    """
    snmp_version = task.host.data.get("snmp_version", 2)
    snmp_port = task.host.data.get("snmp_port", 161)
    
    extras = {"version": snmp_version}
    
    if snmp_version in [1, 2]:
        snmp_community = task.host.data.get("snmp_community")
        if snmp_community:
            extras["community"] = snmp_community
        else:
            logger.warning(f"Host {task.host.name}: SNMP community not found in inventory")
            return
    
    elif snmp_version == 3:
        snmp_user = task.host.data.get("snmp_user")
        if not snmp_user:
            logger.warning(f"Host {task.host.name}: SNMPv3 user not found in inventory")
            return
        
        extras["user"] = snmp_user
        
        # Optional SNMPv3 auth
        snmp_auth_proto = task.host.data.get("snmp_auth_proto")
        snmp_auth_password = task.host.data.get("snmp_auth_password")
        if snmp_auth_proto and snmp_auth_password:
            extras["auth_proto"] = snmp_auth_proto
            extras["auth_password"] = snmp_auth_password
        
        # Optional SNMPv3 privacy
        snmp_priv_proto = task.host.data.get("snmp_priv_proto")
        snmp_priv_password = task.host.data.get("snmp_priv_password")
        if snmp_priv_proto and snmp_priv_password:
            extras["priv_proto"] = snmp_priv_proto
            extras["priv_password"] = snmp_priv_password
    
    task.host.connection_options["puresnmp"] = ConnectionOptions(
        port=snmp_port,
        extras=extras
    )
    logger.debug(f"Host {task.host.name}: puresnmp connection options configured")


def set_connection_options_netmiko(task: Task) -> None:
    """
    Set netmiko connection options from detected device type.
    
    Reads the detected netmiko_device_type from task.host.data and
    configures the netmiko connection plugin.
    
    Args:
        task: Nornir Task object
    """
    netmiko_device_type = task.host.data.get("netmiko_device_type")
    
    if not netmiko_device_type:
        logger.debug(f"Host {task.host.name}: netmiko_device_type not found, skipping netmiko configuration")
        return
    
    task.host.connection_options["netmiko"] = ConnectionOptions(
        platform=netmiko_device_type
    )
    logger.debug(f"Host {task.host.name}: netmiko configured with platform={netmiko_device_type}")


def set_connection_options_scrapli(task: Task) -> None:
    """
    Set scrapli connection options from detected platform.
    
    Reads the detected scrapli_platform from task.host.data and
    configures the scrapli connection plugin. Handles telnet vs SSH scenarios.
    
    Args:
        task: Nornir Task object
    """
    scrapli_platform = task.host.data.get("scrapli_platform")
    
    if not scrapli_platform:
        logger.debug(f"Host {task.host.name}: scrapli_platform not found, skipping scrapli configuration")
        return
    
    extras = {
        "auth_strict_key": False,
    }
    
    # Handle telnet (port 23)
    if task.host.port == 23:
        extras["transport"] = "telnet"
    
    task.host.connection_options["scrapli"] = ConnectionOptions(
        platform=scrapli_platform,
        extras=extras
    )
    logger.debug(f"Host {task.host.name}: scrapli configured with platform={scrapli_platform}")


def set_connection_options_napalm(task: Task) -> None:
    """
    Set napalm connection options from detected driver.
    
    Reads the detected napalm_driver from task.host.data and
    configures the napalm connection plugin. Handles telnet transport.
    
    Args:
        task: Nornir Task object
    """
    napalm_driver = task.host.data.get("napalm_driver")
    
    if not napalm_driver:
        logger.debug(f"Host {task.host.name}: napalm_driver not found, skipping napalm configuration")
        return
    
    extras = {}
    
    # Handle telnet (port 23)
    if task.host.port == 23:
        extras["optional_args"] = {"transport": "telnet"}
    
    task.host.connection_options["napalm"] = ConnectionOptions(
        platform=napalm_driver,
        extras=extras if extras else None
    )
    logger.debug(f"Host {task.host.name}: napalm configured with platform={napalm_driver}")


def set_connection_options(task: Task) -> None:
    """
    Set connection options for netmiko, scrapli, and napalm.
    
    This is a convenience function that calls all three connection option
    setters. Note: puresnmp is excluded as it's typically set initially
    before detection.
    
    Args:
        task: Nornir Task object
    """
    set_connection_options_netmiko(task)
    set_connection_options_scrapli(task)
    set_connection_options_napalm(task)
    logger.debug(f"Host {task.host.name}: all connection options configured")
