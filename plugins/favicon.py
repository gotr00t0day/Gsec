from colorama import Fore
import requests
import codecs
import mmh3
import logging
from urllib.parse import urljoin, urlparse
from typing import Optional
from modules import format_info

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def extract_base_domain(url: str) -> str:
    """
    Extract base domain from URL for display purposes.
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Clean domain name
    """
    try:
        if any(url.startswith(prefix) for prefix in ['http://', 'https://']):
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
                
            return domain
        else:
            # Clean up domain-only input
            domain = url.strip()
            
            # Remove www. prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Remove any trailing slashes or paths
            if '/' in domain:
                domain = domain.split('/')[0]
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            return domain
            
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {str(e)}")
        return url

def favicon_hash(domain: str) -> Optional[str]:
    """
    Calculate favicon hash for a domain with proper error handling.
    
    Args:
        domain: Domain or URL to get favicon from
        
    Returns:
        MMH3 hash of the favicon or None if favicon not found
    """
    if not domain or not domain.strip():
        logger.error("Domain cannot be empty")
        return None
    
    try:
        # Construct proper favicon URL
        favicon_url = urljoin(domain if domain.startswith(('http://', 'https://')) else f'http://{domain}', '/favicon.ico')
        
        # Remove INFO log for cleaner output
        
        # Make request with proper headers and timeout
        response = requests.get(
            favicon_url,
            verify=False,
            timeout=10,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        if response.status_code == 200:
            if not response.content:
                logger.warning(f"Empty favicon content from {favicon_url}")
                return None
            
            # Encode to base64 and calculate hash
            try:
                favicon_b64 = codecs.encode(response.content, "base64")
                favicon_hash_value = mmh3.hash(favicon_b64)
                
                # Extract domain for display
                display_domain = extract_base_domain(domain)
                
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} FavIcon Hash: {Fore.MAGENTA}{favicon_hash_value}")
                print(f"{Fore.YELLOW}    Shodan Dork: org:'{display_domain}' http.favicon.hash:{favicon_hash_value}")
                
                # Remove INFO log for cleaner output
                return str(favicon_hash_value)
                
            except Exception as e:
                logger.error(f"Error calculating favicon hash: {str(e)}")
                return None
                
        else:
            logger.warning(f"Failed to fetch favicon: HTTP {response.status_code}")
            return None
            
    except requests.exceptions.Timeout:
        logger.error(f"Timeout fetching favicon from {domain}")
        return None
        
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error fetching favicon from {domain}")
        return None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error fetching favicon from {domain}: {str(e)}")
        return None
        
    except Exception as e:
        logger.error(f"Unexpected error processing favicon for {domain}: {str(e)}")
        return None

def get_favicon_info(domain: str) -> Optional[dict]:
    """
    Get detailed favicon information including hash and metadata.
    
    Args:
        domain: Domain or URL to analyze
        
    Returns:
        Dictionary with favicon information or None if not found
    """
    if not domain or not domain.strip():
        return None
    
    try:
        favicon_url = urljoin(domain if domain.startswith(('http://', 'https://')) else f'http://{domain}', '/favicon.ico')
        
        response = requests.get(
            favicon_url,
            verify=False,
            timeout=10,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        if response.status_code == 200 and response.content:
            favicon_b64 = codecs.encode(response.content, "base64")
            favicon_hash_value = mmh3.hash(favicon_b64)
            
            return {
                'domain': extract_base_domain(domain),
                'favicon_url': favicon_url,
                'hash': favicon_hash_value,
                'size': len(response.content),
                'content_type': response.headers.get('content-type', 'unknown'),
                'status_code': response.status_code
            }
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting favicon info for {domain}: {str(e)}")
        return None