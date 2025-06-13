from colorama import Fore
from plugins import agent_list
import requests
import logging
from typing import List, Optional, Set
from modules import format_info

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def Get_Options(url: str) -> None:
    """
    Check HTTP OPTIONS method and test for HTTP method override vulnerabilities.
    
    Args:
        url: Target URL to test
    """
    if not url or not url.strip():
        logger.error("URL cannot be empty")
        return
    
    try:
        session = requests.Session()
        
        # Perform OPTIONS request
        response = session.options(url, verify=False, headers=header, timeout=10)
        
        allowed_methods = extract_allowed_methods(response)
        
        if allowed_methods:
            methods_str = ", ".join(sorted(allowed_methods))
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} OPTIONS: {Fore.GREEN}{methods_str}")
            # Remove duplicate logging - the print statement above is sufficient
            
            # Check for dangerous methods
            dangerous_methods = allowed_methods.intersection({'PUT', 'DELETE', 'TRACE', 'PATCH'})
            if dangerous_methods:
                dangerous_str = ", ".join(sorted(dangerous_methods))
                print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} Potentially dangerous methods: {Fore.RED}{dangerous_str}")
            
            # Test for HTTP method override if dangerous methods not explicitly allowed
            test_method_override(session, url, allowed_methods)
        else:
            # Remove INFO log for cleaner output
            pass
            
    except requests.exceptions.Timeout:
        logger.error(f"Timeout while checking OPTIONS for {url}")
        
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error while checking OPTIONS for {url}")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while checking OPTIONS for {url}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Unexpected error checking OPTIONS for {url}: {str(e)}")

def extract_allowed_methods(response: requests.Response) -> Set[str]:
    """
    Extract allowed HTTP methods from response headers.
    
    Args:
        response: HTTP response object
        
    Returns:
        Set of allowed HTTP methods
    """
    allowed_methods = set()
    
    # Check for Allow header
    allow_header = response.headers.get('Allow', '')
    if allow_header:
        # Split by comma and clean up
        methods = [method.strip().upper() for method in allow_header.split(',')]
        allowed_methods.update(methods)
    
    # Also check for Access-Control-Allow-Methods (CORS)
    cors_methods = response.headers.get('Access-Control-Allow-Methods', '')
    if cors_methods:
        methods = [method.strip().upper() for method in cors_methods.split(',')]
        allowed_methods.update(methods)
    
    return allowed_methods

def test_method_override(session: requests.Session, url: str, allowed_methods: Set[str]) -> None:
    """
    Test for HTTP method override vulnerabilities.
    
    Args:
        session: Requests session object
        url: Target URL
        allowed_methods: Set of methods explicitly allowed via OPTIONS
    """
    # Methods to test for override
    test_methods = ['DELETE', 'PUT', 'PATCH']
    
    # Only test methods that aren't explicitly allowed
    methods_to_test = [method for method in test_methods if method not in allowed_methods]
    
    if not methods_to_test:
        return
    
    override_headers = [
        'X-HTTP-Method',
        'X-HTTP-Method-Override',
        'X-Method-Override',
        '_method'
    ]
    
    vulnerable_methods = []
    
    for method in methods_to_test:
        for override_header in override_headers:
            try:
                # Test with GET request and override header
                test_headers = header.copy()
                test_headers[override_header] = method
                
                response = session.get(url, verify=False, headers=test_headers, timeout=10)
                
                # Check if method override was successful
                if is_method_override_successful(response, method):
                    vulnerable_methods.append(f"{method} (via {override_header})")
                    # Remove INFO log - just track the vulnerability
                    break  # Found working override for this method
                    
            except requests.exceptions.RequestException:
                # Ignore request errors during override testing
                continue
            except Exception as e:
                logger.warning(f"Error testing method override {method} via {override_header}: {str(e)}")
                continue
    
    if vulnerable_methods:
        methods_str = ", ".join(vulnerable_methods)
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} HTTP Method Override: {Fore.GREEN}Possible for {Fore.YELLOW}{methods_str}")

def is_method_override_successful(response: requests.Response, method: str) -> bool:
    """
    Determine if HTTP method override was successful based on response.
    
    Args:
        response: HTTP response object
        method: Method that was attempted to override
        
    Returns:
        True if override appears successful, False otherwise
    """
    # Check status code - successful override usually doesn't return 405
    if response.status_code == 405:  # Method Not Allowed
        return False
    
    # Check response content for method indication
    response_text = response.text.lower()
    method_lower = method.lower()
    
    # Look for method name in response
    if method_lower in response_text:
        return True
    
    # Check response headers for method indication
    for header_name, header_value in response.headers.items():
        if method_lower in header_value.lower():
            return True
    
    # If status is 2xx or 3xx, consider it potentially successful
    if 200 <= response.status_code < 400:
        return True
    
    return False

def get_detailed_options_info(url: str) -> Optional[dict]:
    """
    Get detailed information about HTTP OPTIONS and method support.
    
    Args:
        url: Target URL to analyze
        
    Returns:
        Dictionary with detailed OPTIONS information or None if request fails
    """
    try:
        session = requests.Session()
        response = session.options(url, verify=False, headers=header, timeout=10)
        
        allowed_methods = extract_allowed_methods(response)
        
        return {
            'url': url,
            'status_code': response.status_code,
            'allowed_methods': list(allowed_methods),
            'headers': dict(response.headers),
            'dangerous_methods': list(allowed_methods.intersection({'PUT', 'DELETE', 'TRACE', 'PATCH'}))
        }
        
    except Exception as e:
        logger.error(f"Error getting detailed OPTIONS info for {url}: {str(e)}")
        return None
