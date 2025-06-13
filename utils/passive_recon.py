from colorama import Fore
import whois
import dns.resolver
import shodan
import socket
import subprocess
import os
import logging
import shlex
from typing import Optional, List
from urllib.parse import urlparse

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def clean_domain(domain: str) -> str:
    """
    Clean and extract domain name from URL properly.
    
    Args:
        domain: URL or domain string to clean
        
    Returns:
        Clean domain name
    """
    if not domain:
        return ""
    
    # Use urlparse for proper URL handling
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    # Remove www. prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    return domain.strip()

async def whois_scan(domain: str) -> None:
    """
    Perform WHOIS lookup with proper error handling.
    
    Args:
        domain: Target domain to lookup
    """
    try:
        cleaned_domain = clean_domain(domain)
        
        if not cleaned_domain:
            print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Invalid domain for WHOIS lookup")
            return
        
        w = whois.whois(cleaned_domain)
        
        name_servers = w.name_servers
        registrar = w.registrar
        
        if name_servers and None not in name_servers:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Name Servers: {Fore.GREEN}{', '.join(map(str, name_servers))}")
        
        if registrar:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Registrar: {Fore.GREEN}{registrar}")
            
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")

async def dns_info(domain: str) -> None:
    """
    Perform DNS information gathering with proper error handling.
    
    Args:
        domain: Target domain to query
    """
    cleaned_domain = clean_domain(domain)
    
    if not cleaned_domain:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Invalid domain for DNS lookup")
        return
    
    mx_records = []
    
    try:
        # Query MX records
        try:
            mail_exchange = dns.resolver.resolve(cleaned_domain, "MX")
            for mail_info in mail_exchange:
                mx_records.append(mail_info.to_text())
            if mx_records:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} MX: {Fore.GREEN}{', '.join(mx_records)}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Domain does not exist: {cleaned_domain}")
            return
        
        # Query SOA records
        try:
            soa = dns.resolver.resolve(cleaned_domain, "SOA")
            for state_of_authority in soa:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SOA: {Fore.GREEN}{state_of_authority.to_text()}")
        except dns.resolver.NoAnswer:
            pass
        
        # Query CNAME records
        try:
            cname = dns.resolver.resolve(cleaned_domain, "CNAME")
            for cnames in cname:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} CNAME: {Fore.GREEN}{cnames.to_text()}")
        except dns.resolver.NoAnswer:
            pass
            
    except Exception as e:
        logger.error(f"DNS lookup failed for {cleaned_domain}: {str(e)}")

async def shodan_search(domain: str) -> None:
    """
    Perform Shodan search with proper error handling.
    
    Args:
        domain: Target domain to search
    """
    cleaned_domain = clean_domain(domain)
    
    if not cleaned_domain:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Invalid domain for Shodan search")
        return
    
    shodan_key_file = "core/.shodan"
    
    if not os.path.exists(shodan_key_file):
        print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Shodan key file not found: {shodan_key_file}")
        return
    
    try:
        with open(shodan_key_file, "r") as f:
            keys = [x.strip() for x in f.readlines() if x.strip()]
            
            if not keys:
                print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No Shodan API key found")
                return
            
            api = shodan.Shodan(keys[0])
            
            try:
                results = api.search(cleaned_domain)
                
                if results.get('matches'):
                    ips = [result['ip_str'] for result in results['matches'][:10]]  # Limit to first 10
                    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Shodan IPs: {Fore.GREEN}{', '.join(ips)}")
                else:
                    print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No Shodan results found for {cleaned_domain}")
                    
            except shodan.APIError as e:
                print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Shodan API Error: {Fore.RED}{str(e)}")
            except Exception as e:
                logger.error(f"Shodan search error: {str(e)}")
                
    except Exception as e:
        logger.error(f"Error reading Shodan key file: {str(e)}")

async def waybackurls_scan(domain: str) -> None:
    """
    Perform Wayback URLs scan with safe command execution.
    
    Args:
        domain: Target domain to scan
    """
    cleaned_domain = clean_domain(domain)
    
    if not cleaned_domain:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Invalid domain for Wayback scan")
        return
    
    try:
        # Use safe command construction instead of shell=True
        cmd = [
            "waybackpy",
            "--url", cleaned_domain,
            "--user_agent", "Gsec-Security-Scanner",
            "--known_urls"
        ]
        
        # Execute with timeout and proper error handling
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,  # 60 second timeout
            check=False
        )
        
        if result.returncode == 0 and result.stdout:
            # Limit output to prevent huge files
            lines = result.stdout.split('\n')[:10000]
            output = '\n'.join(lines)
            
            os.makedirs("output", exist_ok=True)
            
            with open("output/waybackurls.txt", "w") as f:
                f.write(output)
            
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Waybackurls: {Fore.GREEN}Saved to /output/waybackurls.txt")
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Waybackurls scan failed or no results found")
            
    except subprocess.TimeoutExpired:
        print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Waybackurls scan timed out")
    except FileNotFoundError:
        print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} waybackpy tool not found - please install it")
    except Exception as e:
        logger.error(f"Waybackurls scan error: {str(e)}")

async def certsh(site: str) -> None:
    """
    Perform certificate transparency search with safe execution.
    
    Args:
        site: Target site to scan
    """
    cleaned_domain = clean_domain(site)
    
    if not cleaned_domain:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Invalid domain for certificate search")
        return
    
    try:
        script_path = os.path.join(os.getcwd(), "utils", "subdomainscanners", "certsh.sh")
        
        if not os.path.exists(script_path):
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Certificate script not found: {script_path}")
            return
        
        # Safe command execution
        cmd = ["bash", script_path, cleaned_domain]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False
        )
        
        if result.returncode == 0 and result.stdout:
            os.makedirs("output", exist_ok=True)
            
            with open("output/subdomains.txt", "w") as f:
                f.write(result.stdout)
            
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Subdomains: {Fore.GREEN}Saved to /output/subdomains.txt")
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Certificate search failed or no results")
            
    except subprocess.TimeoutExpired:
        print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Certificate search timed out")
    except Exception as e:
        logger.error(f"Certificate search error: {str(e)}")

async def domains(site: str) -> None:
    """
    Perform domain search with safe execution.
    
    Args:
        site: Target site to scan
    """
    cleaned_domain = clean_domain(site)
    
    if not cleaned_domain:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Invalid domain for domain search")
        return
    
    # Extract base domain name (remove TLD for search)
    base_name = cleaned_domain.split('.')[0] if '.' in cleaned_domain else cleaned_domain
    
    try:
        script_path = os.path.join(os.getcwd(), "utils", "scripts", "domains.sh")
        
        if not os.path.exists(script_path):
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Domain script not found: {script_path}")
            return
        
        # Safe command execution
        cmd = ["bash", script_path, base_name]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False
        )
        
        if result.returncode == 0 and result.stdout:
            os.makedirs("output", exist_ok=True)
            
            with open("output/domains.txt", "w") as f:
                f.write(result.stdout)
            
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Domains: {Fore.GREEN}Saved to /output/domains.txt")
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Domain search failed or no results")
            
    except subprocess.TimeoutExpired:
        print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Domain search timed out")
    except Exception as e:
        logger.error(f"Domain search error: {str(e)}")