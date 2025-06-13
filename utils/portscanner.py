from colorama import Fore
import socket
from modules import urltoip
import ipaddress
import concurrent.futures
import logging
from typing import List, Optional

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Expanded port list for better detection
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 8888, 3000, 3306, 5432, 6379, 27017]

def portscanner(domain: str, custom_ports: Optional[List[int]] = None) -> None:
    """
    Perform port scanning on a domain with proper error handling and performance optimization.
    
    Args:
        domain: Target domain to scan
        custom_ports: Optional custom port list to scan
    """
    if not domain or not domain.strip():
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Domain cannot be empty")
        return
    
    try:
        ip = urltoip.get_ip(domain)
        
        if not ip:
            print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Could not resolve IP for {domain}")
            return
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Invalid IP address: {ip}")
            return
        
        ports_to_scan = custom_ports if custom_ports else COMMON_PORTS
        open_ports = []
        
        # Use ThreadPoolExecutor with limited workers to prevent resource exhaustion
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # Submit all port checks
            future_to_port = {executor.submit(check_port, ip, port): port for port in ports_to_scan}
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_port, timeout=30):
                try:
                    result = future.result(timeout=5)
                    if result:
                        open_ports.append(result)
                except concurrent.futures.TimeoutError:
                    # Skip timeouts - port is likely closed/filtered
                    continue
                except Exception as e:
                    logger.error(f"Error checking port: {str(e)}")
                    continue
        
        if open_ports:
            open_ports.sort()  # Sort for consistent output
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} PORTS: {Fore.GREEN}{', '.join(map(str, open_ports))}")
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No open ports found on common ports")
            
    except socket.error as e:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Socket error: {str(e)}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Port scan interrupted by user")
    except ipaddress.AddressValueError:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} IP address not allowed")
    except Exception as e:
        logger.error(f"Unexpected error in port scanner: {str(e)}")
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Unexpected error during port scan")

def check_port(ip: str, port: int, timeout: int = 3) -> Optional[int]:
    """
    Check if a specific port is open on the target IP.
    
    Args:
        ip: Target IP address
        port: Port number to check
        timeout: Connection timeout in seconds
        
    Returns:
        Port number if open, None if closed/filtered
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Attempt connection
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            return port
        
        return None
        
    except socket.timeout:
        # Port is filtered/closed
        return None
    except socket.error:
        # Connection failed
        return None
    except Exception as e:
        logger.error(f"Error checking port {port}: {str(e)}")
        return None
    finally:
        # Always close the socket to prevent leaks
        if sock:
            try:
                sock.close()
            except:
                pass

def scan_port_range(domain: str, start_port: int, end_port: int) -> None:
    """
    Scan a range of ports on a domain.
    
    Args:
        domain: Target domain
        start_port: Starting port number
        end_port: Ending port number
    """
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Invalid port range: {start_port}-{end_port}")
        return
    
    port_range = list(range(start_port, end_port + 1))
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scanning ports {start_port}-{end_port} on {domain}")
    portscanner(domain, port_range)
