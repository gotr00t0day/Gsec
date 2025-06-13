from colorama import Fore
import json
import logging
import os
from typing import List, Dict, Any, Optional

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def parse_nuclei_json(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse Nuclei JSON output file safely.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        List of parsed JSON objects
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If JSON is invalid
    """
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if os.path.getsize(file_path) == 0:
        # Don't generate warning for empty files - this is normal
        return []
    
    results = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    # Each line should be a valid JSON object
                    json_obj = json.loads(line)
                    results.append(json_obj)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON on line {line_num} in {file_path}: {str(e)}")
                    continue
                    
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        raise
    
    return results

def parse() -> None:
    """
    Parse vulnerabilities from vulnerable.json file and display results.
    """
    try:
        results = parse_nuclei_json("vulnerable.json")
        
        if not results:
            # Don't generate warning for no results - this is normal
            return
        
        # Use consistent output format
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found {len(results)} vulnerability entries")
        
        for result in results:
            display_vulnerability_info(result)
            
    except FileNotFoundError:
        logger.error("vulnerable.json file not found")
    except Exception as e:
        logger.error(f"Error parsing vulnerabilities: {str(e)}")

def mis_parse() -> None:
    """
    Parse misconfigurations from mis_vulnerable.json file and display results.
    """
    try:
        results = parse_nuclei_json("mis_vulnerable.json")
        
        if not results:
            # Don't generate warning for no results - this is normal
            return
        
        # Use consistent output format
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found {len(results)} misconfiguration entries")
        
        for result in results:
            display_misconfiguration_info(result)
            
    except FileNotFoundError:
        logger.error("mis_vulnerable.json file not found")
    except Exception as e:
        logger.error(f"Error parsing misconfigurations: {str(e)}")

def display_vulnerability_info(vuln_data: Dict[str, Any]) -> None:
    """
    Display vulnerability information in a formatted way.
    
    Args:
        vuln_data: Dictionary containing vulnerability data
    """
    try:
        # Extract template ID (CVE)
        template_id = vuln_data.get('template-id', 'Unknown')
        print(f"{Fore.MAGENTA}CVE: {Fore.GREEN}{template_id}")
        
        # Extract matched URL
        matched_at = vuln_data.get('matched-at', 'Unknown')
        print(f"{Fore.MAGENTA}PoC: {Fore.GREEN}{matched_at}")
        
        # Extract vulnerability info
        info = vuln_data.get('info', {})
        if isinstance(info, dict):
            name = info.get('name', 'Unknown vulnerability')
            print(f"{Fore.MAGENTA}Vulnerability: {Fore.GREEN}{name}")
            
            severity = info.get('severity', 'Unknown')
            print(f"{Fore.MAGENTA}Severity: {Fore.GREEN}{severity}")
            
            description = info.get('description', 'No description available')
            print(f"{Fore.MAGENTA}Description: {Fore.GREEN}{description}")
        
        print()  # Add blank line for readability
        
    except Exception as e:
        logger.error(f"Error displaying vulnerability info: {str(e)}")

def display_misconfiguration_info(misc_data: Dict[str, Any]) -> None:
    """
    Display misconfiguration information in a formatted way.
    
    Args:
        misc_data: Dictionary containing misconfiguration data
    """
    try:
        info = misc_data.get('info', {})
        
        if isinstance(info, dict):
            name = info.get('name', 'Unknown misconfiguration')
            print(f"{Fore.MAGENTA}Vulnerability: {Fore.GREEN}{name}")
            
            severity = info.get('severity', 'Unknown')
            print(f"{Fore.MAGENTA}Severity: {Fore.GREEN}{severity}")
            
            description = info.get('description', 'No description available')
            print(f"{Fore.MAGENTA}Description: {Fore.GREEN}{description}")
        
        # Extract matched URL if available
        matched_at = misc_data.get('matched-at', '')
        if matched_at:
            print(f"{Fore.MAGENTA}Found at: {Fore.GREEN}{matched_at}")
        
        print()  # Add blank line for readability
        
    except Exception as e:
        logger.error(f"Error displaying misconfiguration info: {str(e)}")

def get_vulnerability_summary(file_path: str) -> Dict[str, int]:
    """
    Get a summary of vulnerabilities by severity.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        Dictionary with severity counts
    """
    try:
        results = parse_nuclei_json(file_path)
        severity_counts = {}
        
        for result in results:
            info = result.get('info', {})
            if isinstance(info, dict):
                severity = info.get('severity', 'unknown').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return severity_counts
        
    except Exception as e:
        logger.error(f"Error getting vulnerability summary: {str(e)}")
        return {}