"""
Nornir tasks for device detection and data collection.

Provides two main tasks:
- detect: Detect device type and optionally update platform/connection options
- collect: Collect device data for offline analysis and debugging
"""

import logging
from pathlib import Path
from typing import Optional, List
from nornir.core.task import Task, Result
from device_detect import DeviceDetect
from device_detect.exceptions import DeviceDetectError
from nornir_detect.helpers import set_connection_options

logger = logging.getLogger(__name__)


def detect(
    task: Task,
    enable_snmp: bool = True,
    ssh_verification: bool = False,
    ssh_version_filter: bool = True,
    ssh_version_fallback: bool = True,
    ssh_timing_profile: str = "fast",
    include_banners: Optional[bool] = None,
    update_platform: bool = True,
    log_level: str = "INFO"
) -> Result:
    """
    Detect device type using SNMP and/or SSH.
    
    This task uses the device-detect module to automatically identify the
    device type. By default, it updates the host's platform and connection
    options for netmiko, scrapli, and napalm.
    
    Args:
        task: Nornir Task object
        enable_snmp: Enable SNMP detection (default: True)
        ssh_verification: Verify SNMP results via SSH (default: False)
        ssh_version_filter: Enable SSH version filtering (default: True)
        ssh_version_fallback: Test non-matching device types if no match (default: True)
        ssh_timing_profile: SSH timing profile - 'fast', 'normal', or 'slow' (default: 'fast')
        include_banners: Include SSH banner data in results (default: None, auto-detect)
        update_platform: Update host platform and connection options (default: True)
        log_level: Logging level for device-detect module (default: 'INFO')
    
    Returns:
        Result object containing DetectionResult with:
            - device_type: Detected device type (e.g., 'cisco_ios')
            - score: Confidence score (0-100)
            - method: Detection method used ('SNMP', 'SSH', 'SNMP+SSH')
            - Framework driver mappings (netmiko, scrapli, napalm, etc.)
            - Timing information
            - error_records: List of ErrorRecord objects with detailed error/warning context (v0.11.0+)
            - has_errors/has_warnings: Boolean properties for error/warning detection (v0.11.0+)
            - primary_error: Highest priority error for troubleshooting (v0.11.0+)
    
    Example:
        >>> from nornir import InitNornir
        >>> from nornir_detect import detect
        >>> nr = InitNornir(inventory="inventory.yaml")
        >>> result = nr.run(task=detect)
        >>> for host, task_result in result.items():
        ...     detection = task_result.result
        ...     print(f"{host}: {detection.device_type}")
    """
    logger.info(f"Starting device detection for {task.host.name}")
    
    try:
        # Extract credentials from inventory
        hostname = task.host.hostname
        
        # SSH credentials
        ssh_username = task.host.username
        ssh_password = task.host.password
        ssh_enable_password = task.host.data.get("ssh_enable_password")
        ssh_port = task.host.port or 22
        
        # SNMP credentials
        snmp_community = task.host.data.get("snmp_community")
        snmp_version = task.host.data.get("snmp_version", 2)
        snmp_user = task.host.data.get("snmp_user")
        snmp_auth_proto = task.host.data.get("snmp_auth_proto")
        snmp_auth_password = task.host.data.get("snmp_auth_password")
        snmp_priv_proto = task.host.data.get("snmp_priv_proto")
        snmp_priv_password = task.host.data.get("snmp_priv_password")
        
        # Create DeviceDetect instance
        detector = DeviceDetect(
            hostname=hostname,
            # SNMP parameters
            snmp_community=snmp_community,
            snmp_version=snmp_version,
            snmp_user=snmp_user,
            snmp_auth_proto=snmp_auth_proto,
            snmp_auth_password=snmp_auth_password,
            snmp_priv_proto=snmp_priv_proto,
            snmp_priv_password=snmp_priv_password,
            # SSH parameters
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            ssh_enable_password=ssh_enable_password,
            ssh_port=ssh_port,
            # SSH options
            ssh_version_filter=ssh_version_filter,
            ssh_version_fallback=ssh_version_fallback,
            ssh_timing_profile=ssh_timing_profile,
            # Detection options
            enable_snmp=enable_snmp,
            ssh_verification=ssh_verification,
            include_banners=include_banners,
            log_level=log_level,
        )
        
        # Run detection
        detection_result = detector.detect()
        
        # Check if detection was successful
        if not detection_result.success or not detection_result.device_type:
            # Build comprehensive error message for root cause analysis
            error_parts = [f"Device detection failed for {task.host.name}"]
            
            # Add primary error (v0.11.0: using ErrorRecord)
            if detection_result.primary_error:
                primary = detection_result.primary_error
                error_parts.append(f"Primary Error: {primary.message}")
                error_parts.append(f"Error Type: {primary.error_type}")
                if primary.phase:
                    error_parts.append(f"Phase: {primary.phase}")
            
            # Add all errors for complete diagnostics (v0.11.0: using ErrorRecord list)
            if detection_result.has_errors:
                error_parts.append("\nDetailed Error History:")
                for idx, err_record in enumerate(detection_result.errors, 1):
                    method = err_record.method.upper() if err_record.method else 'UNKNOWN'
                    error_parts.append(
                        f"  {idx}. [{method}] {err_record.error_type}: {err_record.message}"
                    )
                    if err_record.context:
                        error_parts.append(f"      Context: {err_record.context}")
            
            # Add warnings if any (v0.11.0: using ErrorRecord list)
            if detection_result.has_warnings:
                error_parts.append("\nWarnings:")
                for warn_record in detection_result.warnings:
                    error_parts.append(f"  - {warn_record.message}")
            
            comprehensive_error = "\n".join(error_parts)
            logger.error(comprehensive_error)
            
            return Result(
                host=task.host,
                result=detection_result,
                failed=True,
                exception=Exception(comprehensive_error)
            )
        
        logger.info(
            f"Host {task.host.name}: detected {detection_result.device_type} "
            f"(score: {detection_result.score}, method: {detection_result.method})"
        )
        
        # Log warnings if any (even for successful detections) (v0.11.0: using ErrorRecord list)
        if detection_result.has_warnings:
            logger.warning(f"Host {task.host.name}: Detection succeeded with warnings:")
            for warn_record in detection_result.warnings:
                logger.warning(f"  - {warn_record.message}")
        
        # Update platform and connection options if requested
        if update_platform:
            # Update host.platform
            if detection_result.napalm_driver:
                task.host.platform = detection_result.napalm_driver
                logger.debug(f"Host {task.host.name}: platform set to {detection_result.napalm_driver}")
            
            # Update host.data with detected drivers
            if detection_result.nornir_driver:
                task.host.data["netmiko_device_type"] = detection_result.nornir_driver
            if detection_result.scrapli_driver:
                task.host.data["scrapli_platform"] = detection_result.scrapli_driver
            if detection_result.napalm_driver:
                task.host.data["napalm_driver"] = detection_result.napalm_driver
            
            # Configure connection options for netmiko, scrapli, napalm
            set_connection_options(task)
            logger.info(f"Host {task.host.name}: platform and connection options updated")
        
        return Result(
            host=task.host,
            result=detection_result,
            failed=False
        )
    
    except DeviceDetectError as e:
        error_msg = f"DeviceDetect error for {task.host.name}: {str(e)}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            result=str(e),
            failed=True,
            exception=e
        )
    
    except Exception as e:
        error_msg = f"Unexpected error during detection for {task.host.name}: {str(e)}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            result=str(e),
            failed=True,
            exception=e
        )


def collect(
    task: Task,
    snmp_only: bool = False,
    ssh_only: bool = False,
    collect_ssh_commands: bool = False,
    additional_commands: Optional[List[str]] = None,
    sanitize_output: bool = False,
    save_to_file: bool = True,
    output_path: Optional[str] = None,
    output_format: str = 'json',
    log_level: str = "INFO"
) -> Result:
    """
    Collect device data for offline analysis or debugging.
    
    This task collects SNMP and/or SSH data from devices without performing
    device type detection. Data can be saved to files for later offline analysis.
    
    Args:
        task: Nornir Task object
        snmp_only: Only collect SNMP data (default: False)
        ssh_only: Only collect SSH data (default: False)
        collect_ssh_commands: Collect all SSH detection command outputs (default: False)
        additional_commands: List of additional commands to collect (default: None)
        sanitize_output: Remove escape characters from command outputs (default: False)
        save_to_file: Save collected data to file (default: True)
        output_path: Custom output path, supports {host} placeholder (default: 'collected_data/{host}.json')
        output_format: Output format - 'json', 'csv', 'excel', 'yaml' (default: 'json')
        log_level: Logging level for device-detect module (default: 'INFO')
    
    Returns:
        Result object containing DetectionResult with collected data:
            - snmp_data: Collected SNMP data (if SNMP used)
            - ssh_data: Collected SSH data (if SSH used)
            - operation_mode: 'collect'
            - timing: Collection timing information
    
    Example:
        >>> from nornir import InitNornir
        >>> from nornir_detect import collect
        >>> nr = InitNornir(inventory="inventory.yaml")
        >>> result = nr.run(
        ...     task=collect,
        ...     collect_ssh_commands=True,
        ...     save_to_file=True
        ... )
    """
    logger.info(f"Starting data collection for {task.host.name}")
    
    try:
        # Extract credentials from inventory
        hostname = task.host.hostname
        
        # SSH credentials
        ssh_username = task.host.username
        ssh_password = task.host.password
        ssh_enable_password = task.host.data.get("ssh_enable_password")
        ssh_port = task.host.port or 22
        
        # SNMP credentials
        snmp_community = task.host.data.get("snmp_community")
        snmp_version = task.host.data.get("snmp_version", 2)
        snmp_user = task.host.data.get("snmp_user")
        snmp_auth_proto = task.host.data.get("snmp_auth_proto")
        snmp_auth_password = task.host.data.get("snmp_auth_password")
        snmp_priv_proto = task.host.data.get("snmp_priv_proto")
        snmp_priv_password = task.host.data.get("snmp_priv_password")
        
        # Create DeviceDetect instance
        detector = DeviceDetect(
            hostname=hostname,
            # SNMP parameters
            snmp_community=snmp_community,
            snmp_version=snmp_version,
            snmp_user=snmp_user,
            snmp_auth_proto=snmp_auth_proto,
            snmp_auth_password=snmp_auth_password,
            snmp_priv_proto=snmp_priv_proto,
            snmp_priv_password=snmp_priv_password,
            # SSH parameters
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            ssh_enable_password=ssh_enable_password,
            ssh_port=ssh_port,
            log_level=log_level,
        )
        
        # Run collection
        collection_result = detector.collect(
            snmp_only=snmp_only,
            ssh_only=ssh_only,
            collect_ssh_commands=collect_ssh_commands,
            additional_commands=additional_commands,
            sanitize_output=sanitize_output
        )
        
        # Check if collection was successful
        if not collection_result.success:
            # Build comprehensive error message for root cause analysis
            error_parts = [f"Data collection failed for {task.host.name}"]
            
            # Add primary error (v0.11.0: using ErrorRecord)
            if collection_result.primary_error:
                primary = collection_result.primary_error
                error_parts.append(f"Primary Error: {primary.message}")
                error_parts.append(f"Error Type: {primary.error_type}")
                if primary.phase:
                    error_parts.append(f"Phase: {primary.phase}")
            
            # Add all errors for complete diagnostics (v0.11.0: using ErrorRecord list)
            if collection_result.has_errors:
                error_parts.append("\nDetailed Error History:")
                for idx, err_record in enumerate(collection_result.errors, 1):
                    method = err_record.method.upper() if err_record.method else 'UNKNOWN'
                    error_parts.append(
                        f"  {idx}. [{method}] {err_record.error_type}: {err_record.message}"
                    )
                    if err_record.context:
                        error_parts.append(f"      Context: {err_record.context}")
            
            # Add warnings if any (v0.11.0: using ErrorRecord list)
            if collection_result.has_warnings:
                error_parts.append("\nWarnings:")
                for warn_record in collection_result.warnings:
                    error_parts.append(f"  - {warn_record.message}")
            
            comprehensive_error = "\n".join(error_parts)
            logger.error(comprehensive_error)
            
            return Result(
                host=task.host,
                result=collection_result,
                failed=True,
                exception=Exception(comprehensive_error)
            )
        
        logger.info(
            f"Host {task.host.name}: data collected "
            f"(method: {collection_result.method})"
        )
        
        # Log warnings if any (even for successful collections) (v0.11.0: using ErrorRecord list)
        if collection_result.has_warnings:
            logger.warning(f"Host {task.host.name}: Collection succeeded with warnings:")
            for warn_record in collection_result.warnings:
                logger.warning(f"  - {warn_record.message}")
        
        # Save to file if requested
        if save_to_file:
            # Determine output path
            if output_path:
                # Replace {host} placeholder
                file_path = output_path.replace("{host}", task.host.name)
            else:
                # Default path: collected_data/{hostname}.{ext}
                ext_map = {'json': 'json', 'csv': 'csv', 'excel': 'xlsx', 'yaml': 'yaml'}
                ext = ext_map.get(output_format, 'json')
                file_path = f"collected_data/{task.host.name}.{ext}"
            
            # Create directory if needed
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Save the file
            saved_path = collection_result.save_to_file(
                path=file_path,
                format=output_format
            )
            logger.info(f"Host {task.host.name}: data saved to {saved_path}")
        
        return Result(
            host=task.host,
            result=collection_result,
            failed=False
        )
    
    except DeviceDetectError as e:
        error_msg = f"DeviceDetect error for {task.host.name}: {str(e)}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            result=str(e),
            failed=True,
            exception=e
        )
    
    except Exception as e:
        error_msg = f"Unexpected error during collection for {task.host.name}: {str(e)}"
        logger.error(error_msg)
        return Result(
            host=task.host,
            result=str(e),
            failed=True,
            exception=e
        )
