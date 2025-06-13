from modules import sub_output, urltoip
from colorama import Fore
import os
import subprocess
import logging

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def vulners_scan(domain: str) -> str:
    """
    Perform Nmap vulnerability scan using vulners and vuln scripts.
    
    Args:
        domain: Target domain to scan
        
    Returns:
        Status message
    """
    if not domain or not domain.strip():
        return "Error: Domain cannot be empty"
    
    try:
        # Clean domain properly
        cleaned_domain = domain.strip()
        
        # Remove protocol prefixes
        for prefix in ["https://www.", "http://www.", "https://", "http://"]:
            if cleaned_domain.startswith(prefix):
                cleaned_domain = cleaned_domain[len(prefix):]
                break
        
        # Remove trailing slash if present
        if cleaned_domain.endswith('/'):
            cleaned_domain = cleaned_domain[:-1]
        
        # Get IP address
        ip = urltoip.get_ip(cleaned_domain)
        
        if not ip:
            return f"Error: Could not resolve IP for domain: {cleaned_domain}"
        
        # Ensure output directory exists
        output_dir = os.path.join(os.getcwd(), "output")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        output_file = os.path.join(output_dir, "nmap_results.txt")
        
        # Build proper nmap command - fix the script syntax and avoid shell redirection
        nmap_cmd = [
            "nmap",
            "--script", "vulners,vuln",  # Fixed: removed space after comma
            ip,
            "-v",
            "-p80,443",
            "-T4",
            "-Pn"
        ]
        
        try:
            # Execute nmap command directly without shell=True and handle output redirection properly
            with open(output_file, 'w') as f:
                result = subprocess.run(
                    nmap_cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
            
            if result.returncode == 0:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Nmap Vulnerability Scan: {Fore.GREEN}Results saved to {output_file}")
                return f"Nmap scan completed successfully for {ip}"
            else:
                if result.stderr:
                    logger.error(f"Nmap scan failed: {result.stderr}")
                print(f"{Fore.YELLOW}[-] {Fore.CYAN}-{Fore.WHITE} Nmap scan completed with warnings - check {output_file}")
                return f"Nmap scan completed with warnings for {ip}"
                
        except subprocess.TimeoutExpired:
            # Remove error log message to keep output clean - timeout is expected for long scans
            print(f"{Fore.YELLOW}[-] {Fore.CYAN}-{Fore.WHITE} Nmap vulnerability scan timed out (5 min limit)")
            return "Nmap scan timed out"
            
        except FileNotFoundError:
            logger.error("Nmap not found - please install nmap")
            print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Nmap not found - please install nmap")
            return "Error: Nmap not found"
            
    except Exception as e:
        logger.error(f"Error during vulnerability scan: {str(e)}")
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error during vulnerability scan: {str(e)}")
        return f"Error during vulnerability scan: {str(e)}" 
