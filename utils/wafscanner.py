from colorama import Fore
from bs4 import BeautifulSoup
from plugins import agent_list
import requests
import logging
import re
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Set, Optional

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings()

class WAFScanner:
    """Advanced WAF detection scanner with comprehensive fingerprinting capabilities."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': agent_list.get_useragent()
        })
        
        # Comprehensive WAF detection signatures
        self.waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id', 'server: cloudflare'],
                'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
                'content': ['cloudflare', 'attention required!', 'checking your browser'],
                'status_codes': [403, 503, 525, 526]
            },
            'AWS WAF': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-apigw-id'],
                'content': ['aws waf', 'blocked by aws waf'],
                'status_codes': [403]
            },
            'ModSecurity': {
                'headers': ['server: apache', 'server: nginx'],
                'content': ['mod_security', 'modsecurity', 'not acceptable'],
                'status_codes': [406, 501, 403]
            },
            'Akamai': {
                'headers': ['akamai-ghost-ip', 'akamai-grn', 'server: akamaigh'],
                'content': ['akamai', 'reference #'],
                'status_codes': [403]
            },
            'Incapsula': {
                'headers': ['x-iinfo', 'x-cdn'],
                'cookies': ['incap_ses', 'visid_incap'],
                'content': ['incapsula', 'request unsuccessful'],
                'status_codes': [403]
            },
            'Sucuri': {
                'headers': ['server: sucuri', 'x-sucuri-id', 'x-sucuri-cache'],
                'content': ['sucuri website firewall', 'access denied'],
                'status_codes': [403]
            },
            'F5 BIG-IP': {
                'headers': ['server: bigip', 'x-waf-event-info'],
                'cookies': ['bigipserver', 'f5-ltm-pool'],
                'content': ['the requested url was rejected', 'f5 networks'],
                'status_codes': [403]
            },
            'Barracuda': {
                'headers': ['server: barracuda'],
                'content': ['barracuda', 'blocked by barracuda'],
                'status_codes': [403]
            },
            'FortiWeb': {
                'headers': ['server: fortiweb'],
                'content': ['fortinet', 'blocked by fortiweb'],
                'status_codes': [403]
            },
            'Citrix NetScaler': {
                'headers': ['via: netscaler', 'cneonction', 'ns_af'],
                'content': ['netscaler', 'citrix'],
                'status_codes': [403]
            },
            'Imperva': {
                'headers': ['x-iinfo'],
                'content': ['imperva', 'blocked by imperva'],
                'status_codes': [403]
            },
            'Azure Front Door': {
                'headers': ['x-azure-ref', 'x-fd-healthprobe'],
                'content': ['azure front door'],
                'status_codes': [403]
            }
        }
        
        # Test payloads to trigger WAF responses
        self.test_payloads = [
            "' OR 1=1--",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "'; DROP TABLE users--",
            "<img src=x onerror=alert(1)>",
            "UNION SELECT * FROM users",
            "<?php system($_GET['cmd']); ?>",
            "%3Cscript%3Ealert%281%29%3C/script%3E"
        ]
        
        self.detected_wafs = set()
        
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def normalize_url(self, url: str) -> str:
        """Ensure URL has proper format."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def detect_waf_by_headers(self, response: requests.Response) -> Set[str]:
        """
        Detect WAF by analyzing response headers.
        
        Args:
            response: HTTP response object
            
        Returns:
            Set of detected WAF names
        """
        detected = set()
        
        try:
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            for waf_name, signatures in self.waf_signatures.items():
                if 'headers' in signatures:
                    for header_sig in signatures['headers']:
                        if ':' in header_sig:
                            # Header with value (e.g., 'server: cloudflare')
                            header_key, header_value = header_sig.split(':', 1)
                            header_key = header_key.strip().lower()
                            header_value = header_value.strip().lower()
                            
                            if header_key in headers and header_value in headers[header_key]:
                                detected.add(waf_name)
                                break
                        else:
                            # Header key only
                            if header_sig.lower() in headers:
                                detected.add(waf_name)
                                break
                                
        except Exception as e:
            logger.error(f"Error detecting WAF by headers: {str(e)}")
        
        return detected
    
    def detect_waf_by_cookies(self, response: requests.Response) -> Set[str]:
        """
        Detect WAF by analyzing response cookies.
        
        Args:
            response: HTTP response object
            
        Returns:
            Set of detected WAF names
        """
        detected = set()
        
        try:
            cookie_names = [cookie.name.lower() for cookie in response.cookies]
            
            for waf_name, signatures in self.waf_signatures.items():
                if 'cookies' in signatures:
                    for cookie_sig in signatures['cookies']:
                        if cookie_sig.lower() in cookie_names:
                            detected.add(waf_name)
                            break
                            
        except Exception as e:
            logger.error(f"Error detecting WAF by cookies: {str(e)}")
        
        return detected
    
    def detect_waf_by_content(self, response: requests.Response) -> Set[str]:
        """
        Detect WAF by analyzing response content.
        
        Args:
            response: HTTP response object
            
        Returns:
            Set of detected WAF names
        """
        detected = set()
        
        try:
            content = response.text.lower()
            
            for waf_name, signatures in self.waf_signatures.items():
                if 'content' in signatures:
                    for content_sig in signatures['content']:
                        if content_sig.lower() in content:
                            detected.add(waf_name)
                            break
                            
        except Exception as e:
            logger.error(f"Error detecting WAF by content: {str(e)}")
        
        return detected
    
    def detect_waf_by_status_code(self, response: requests.Response, waf_name: str) -> bool:
        """
        Check if status code matches WAF signature.
        
        Args:
            response: HTTP response object
            waf_name: WAF name to check
            
        Returns:
            True if status code matches, False otherwise
        """
        try:
            if waf_name in self.waf_signatures:
                expected_codes = self.waf_signatures[waf_name].get('status_codes', [])
                return response.status_code in expected_codes
        except Exception as e:
            logger.error(f"Error checking WAF status code: {str(e)}")
        
        return False
    
    def test_waf_with_payloads(self, url: str) -> Set[str]:
        """
        Test WAF detection using malicious payloads.
        
        Args:
            url: Target URL to test
            
        Returns:
            Set of detected WAF names
        """
        detected = set()
        
        for payload in self.test_payloads:
            try:
                # Test with different injection points
                test_urls = [
                    f"{url}?test={payload}",
                    f"{url}#{payload}",
                    f"{url}/{payload}"
                ]
                
                for test_url in test_urls:
                    try:
                        response = self.session.get(test_url, timeout=10, verify=False)
                        
                        # Analyze response for WAF signatures
                        detected.update(self.detect_waf_by_headers(response))
                        detected.update(self.detect_waf_by_cookies(response))
                        detected.update(self.detect_waf_by_content(response))
                        
                        # Check for blocked status codes
                        if response.status_code in [403, 406, 501, 503]:
                            for waf_name in self.waf_signatures.keys():
                                if self.detect_waf_by_status_code(response, waf_name):
                                    detected.add(waf_name)
                        
                        # Don't test all URLs if we found something
                        if detected:
                            break
                            
                    except requests.exceptions.RequestException:
                        continue
                
                # Rate limiting
                import time
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error testing payload {payload}: {str(e)}")
                continue
        
        return detected
    
    def detect_security_headers(self, response: requests.Response) -> Dict[str, bool]:
        """
        Detect security headers that might indicate WAF presence.
        
        Args:
            response: HTTP response object
            
        Returns:
            Dictionary of security headers and their presence
        """
        security_headers = {
            'X-Content-Security-Policy': False,
            'Content-Security-Policy': False,
            'X-Frame-Options': False,
            'X-XSS-Protection': False,
            'Strict-Transport-Security': False,
            'X-Content-Type-Options': False,
            'Referrer-Policy': False,
            'Permissions-Policy': False
        }
        
        try:
            for header in security_headers.keys():
                if header.lower() in [h.lower() for h in response.headers.keys()]:
                    security_headers[header] = True
        except Exception as e:
            logger.error(f"Error detecting security headers: {str(e)}")
        
        return security_headers
    
    def scan_waf(self, domain: str) -> Dict[str, any]:
        """
        Comprehensive WAF detection scan.
        
        Args:
            domain: Target domain to scan
            
        Returns:
            Dictionary with scan results
        """
        results = {
            'detected_wafs': set(),
            'security_headers': {},
            'confidence': 'Low',
            'additional_info': []
        }
        
        try:
            url = self.normalize_url(domain)
            
            # Initial request
            response = self.session.get(url, timeout=15, verify=False)
            
            # Detect by headers, cookies, and content
            results['detected_wafs'].update(self.detect_waf_by_headers(response))
            results['detected_wafs'].update(self.detect_waf_by_cookies(response))
            results['detected_wafs'].update(self.detect_waf_by_content(response))
            
            # Detect security headers
            results['security_headers'] = self.detect_security_headers(response)
            
            # Test with malicious payloads for better detection
            payload_detected = self.test_waf_with_payloads(url)
            results['detected_wafs'].update(payload_detected)
            
            # Determine confidence level
            if results['detected_wafs']:
                if len(results['detected_wafs']) > 1:
                    results['confidence'] = 'High'
                else:
                    results['confidence'] = 'Medium'
            elif any(results['security_headers'].values()):
                results['confidence'] = 'Low'
                results['additional_info'].append('Security headers present - possible WAF')
            
            # Additional checks
            if response.status_code in [403, 406, 501, 503]:
                results['additional_info'].append(f'Suspicious status code: {response.status_code}')
            
        except requests.exceptions.Timeout:
            results['additional_info'].append('Request timeout - possible rate limiting')
        except requests.exceptions.ConnectionError:
            results['additional_info'].append('Connection error')
        except Exception as e:
            logger.error(f"WAF scan error: {str(e)}")
            results['additional_info'].append(f'Scan error: {str(e)}')
        
        return results

def main(domain: str) -> None:
    """
    Main WAF detection function with improved accuracy and error handling.
    
    Args:
        domain: Target domain to scan for WAF presence
    """
    if not domain or not domain.strip():
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Domain cannot be empty")
        return
    
    scanner = WAFScanner()
    
    try:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Starting WAF detection for: {Fore.GREEN}{domain}")
        
        results = scanner.scan_waf(domain)
        
        if results['detected_wafs']:
            waf_list = list(results['detected_wafs'])
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} WAF Detected: {Fore.GREEN}{', '.join(waf_list)}")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Confidence: {Fore.YELLOW}{results['confidence']}")
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No WAF detected")
        
        # Report security headers
        active_headers = [k for k, v in results['security_headers'].items() if v]
        if active_headers:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Security Headers: {Fore.GREEN}{len(active_headers)} found")
        
        # Report additional info
        for info in results['additional_info']:
            print(f"{Fore.CYAN}[*] {Fore.CYAN}-{Fore.WHITE} {info}")
        
    except Exception as e:
        logger.error(f"WAF detection error: {str(e)}")
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error during WAF detection: {str(e)}")

# Legacy function names for backward compatibility
def waf_headers(domain: str) -> bool:
    """Legacy function for backward compatibility."""
    scanner = WAFScanner()
    try:
        url = scanner.normalize_url(domain)
        response = scanner.session.get(url, timeout=10, verify=False)
        return bool(scanner.detect_waf_by_headers(response))
    except:
        return False

def waf_ssl_tls_config(domain: str) -> bool:
    """Legacy function for backward compatibility."""
    return waf_headers(domain)

def waf_url_structure(domain: str) -> bool:
    """Legacy function for backward compatibility."""
    return waf_headers(domain)

def waf_response_code(domain: str) -> bool:
    """Legacy function for backward compatibility."""
    return waf_headers(domain)

def waf_text(domain: str) -> bool:
    """Legacy function for backward compatibility."""
    return waf_headers(domain)






