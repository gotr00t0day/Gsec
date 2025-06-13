from libnmap.parser import NmapParser
import logging
import os
from typing import List, Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define web ports as a set for O(1) lookup
WEB_PORTS = {'80', '443', '8080', '8443', '8000', '8888', '9000', '9080', '9443'}

def parse_scan(xml_file: str = 'nmap_results.xml') -> Optional[str]:
    """
    Parse Nmap XML results and extract web service ports.
    
    Args:
        xml_file: Path to the Nmap XML results file
        
    Returns:
        Newline-separated string of web ports found, or None if parsing fails
        
    Raises:
        FileNotFoundError: If XML file doesn't exist
        Exception: If parsing fails
    """
    if not os.path.exists(xml_file):
        logger.error(f"Nmap XML file not found: {xml_file}")
        raise FileNotFoundError(f"XML file not found: {xml_file}")
    
    try:
        # Parse the Nmap XML file
        nmap_report = NmapParser.parse_fromfile(xml_file)
        
        if not nmap_report.hosts:
            logger.warning("No hosts found in Nmap results")
            return ""
        
        web_ports_found: List[str] = []
        service_info: List[str] = []
        
        # Process each host
        for host in nmap_report.hosts:
            host_ip = host.address
            logger.info(f"Processing host: {host_ip}")
            
            # Process each service
            for service in host.services:
                port_str = str(service.port)
                service_name = service.service or "unknown"
                banner = service.banner or "no banner"
                
                # Store detailed service information
                service_info.append(f"{host_ip}:{port_str}:{service_name}:{banner}")
                
                # Check if it's a web port
                if port_str in WEB_PORTS:
                    web_ports_found.append(port_str)
                    logger.info(f"Web port found: {port_str} ({service_name})")
                
                # Also check service name for web services
                elif any(web_service in service_name.lower() for web_service in ['http', 'https', 'web']):
                    web_ports_found.append(port_str)
                    logger.info(f"Web service found on port {port_str}: {service_name}")
        
        # Remove duplicates while preserving order
        unique_web_ports = list(dict.fromkeys(web_ports_found))
        
        # Log service information for debugging
        logger.info(f"Total services found: {len(service_info)}")
        logger.info(f"Web ports identified: {unique_web_ports}")
        
        return "\n".join(unique_web_ports) if unique_web_ports else ""
        
    except Exception as e:
        logger.error(f"Error parsing Nmap XML file '{xml_file}': {str(e)}")
        raise

def get_service_details(xml_file: str = 'nmap_results.xml') -> List[dict]:
    """
    Get detailed service information from Nmap results.
    
    Args:
        xml_file: Path to the Nmap XML results file
        
    Returns:
        List of dictionaries containing service details
    """
    if not os.path.exists(xml_file):
        logger.error(f"Nmap XML file not found: {xml_file}")
        return []
    
    try:
        nmap_report = NmapParser.parse_fromfile(xml_file)
        services = []
        
        for host in nmap_report.hosts:
            for service in host.services:
                service_dict = {
                    'host': host.address,
                    'port': service.port,
                    'protocol': service.protocol,
                    'service': service.service or "unknown",
                    'state': service.state,
                    'banner': service.banner or "",
                    'version': service.service_version or ""
                }
                services.append(service_dict)
        
        return services
        
    except Exception as e:
        logger.error(f"Error getting service details from '{xml_file}': {str(e)}")
        return []