import socket
import logging
from urllib.parse import urlparse
from typing import Optional
from modules import format_info

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def get_ip(domain: str) -> Optional[str]:
    """
    Get IP address from domain name with proper URL parsing and error handling.
    
    Args:
        domain: URL or domain name to resolve
        
    Returns:
        IP address string or None if resolution fails
        
    Raises:
        ValueError: If domain is empty or invalid
    """
    if not domain or not domain.strip():
        raise ValueError("Domain cannot be empty")
    
    try:
        # Clean and extract domain name properly
        cleaned_domain = extract_domain(domain.strip())
        
        if not cleaned_domain:
            logger.error(f"Could not extract domain from: {domain}")
            return None
        
        # Resolve domain to IP
        ip_address = socket.gethostbyname(cleaned_domain)
        # Use consistent format instead of INFO log
        # format_info(f"Resolved {cleaned_domain} to {ip_address}")
        return ip_address
        
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {domain}: {str(e)}")
        return None
        
    except UnicodeError as e:
        logger.error(f"Unicode error processing domain {domain}: {str(e)}")
        return None
        
    except Exception as e:
        logger.error(f"Unexpected error resolving {domain}: {str(e)}")
        return None

def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain name from URL string properly handling various URL formats.
    
    Args:
        url: URL string to extract domain from
        
    Returns:
        Clean domain name or None if extraction fails
    """
    try:
        # If it looks like a URL, parse it properly
        if any(url.startswith(prefix) for prefix in ['http://', 'https://', 'ftp://', 'ftps://']):
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
                
            return domain
        
        # If it's just a domain, clean it up
        else:
            # Remove common prefixes that might be accidentally included
            domain = url
            
            # Remove www. prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Remove any trailing slashes or paths
            if '/' in domain:
                domain = domain.split('/')[0]
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Basic validation - should contain at least one dot for valid domain
            if '.' in domain and len(domain) > 3:
                return domain
            else:
                logger.warning(f"Domain validation failed for: {domain}")
                return None
                
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {str(e)}")
        return None