import requests
from colorama import Fore
import json
import socket
import urllib3
import logging
from urllib.parse import urlparse
from typing import Optional, Dict, Any
import time
from modules import format_info

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain name from URL properly using urlparse.
    
    Args:
        url: URL string to extract domain from
        
    Returns:
        Clean domain name or None if extraction fails
    """
    try:
        # If it looks like a URL, parse it properly
        if any(url.startswith(prefix) for prefix in ['http://', 'https://']):
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
                
            return domain
        
        # If it's just a domain, clean it up
        else:
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
            
            return domain if domain else None
                
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {str(e)}")
        return None

def get_geolocation_data(ip: str, max_retries: int = 3) -> Optional[Dict[str, Any]]:
    """
    Get geolocation data for an IP address with retry logic.
    
    Args:
        ip: IP address to look up
        max_retries: Maximum number of retry attempts
        
    Returns:
        Dictionary containing geolocation data or None if lookup fails
    """
    url = f'https://geolocation-db.com/jsonp/{ip}'
    
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                timeout=10,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            
            if response.status_code == 200:
                # Parse JSONP response
                content = response.content.decode('utf-8')
                
                # Extract JSON from JSONP wrapper
                if '(' in content and ')' in content:
                    start = content.find('(') + 1
                    end = content.rfind(')')
                    json_str = content[start:end]
                    
                    try:
                        data = json.loads(json_str)
                        return data
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON response: {str(e)}")
                        return None
                        
            else:
                logger.warning(f"API returned status {response.status_code} for IP {ip}")
                
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on attempt {attempt + 1} for IP {ip}")
            
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error on attempt {attempt + 1} for IP {ip}")
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request error on attempt {attempt + 1} for IP {ip}: {str(e)}")
        
        # Wait before retrying (exponential backoff)
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            time.sleep(wait_time)
    
    logger.error(f"Failed to get geolocation data for IP {ip} after {max_retries} attempts")
    return None

def scan_ip(domain: str) -> None:
    """
    Perform geolocation scanning for a domain with proper error handling.
    
    Args:
        domain: Domain or URL to scan
    """
    if not domain or not domain.strip():
        logger.error("Domain cannot be empty")
        return
    
    try:
        # Extract clean domain name
        clean_domain = extract_domain_from_url(domain.strip())
        
        if not clean_domain:
            logger.error(f"Could not extract valid domain from: {domain}")
            return
        
        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(clean_domain)
            # Remove duplicate resolution message - it's already shown by urltoip module
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {clean_domain}: {str(e)}")
            return
        
        # Get geolocation data
        geo_data = get_geolocation_data(ip)
        
        if not geo_data:
            logger.warning(f"No geolocation data available for {ip}")
            return
        
        # Extract and display location information
        location_info = []
        
        country = geo_data.get('country_name')
        if country and country != 'Not found':
            location_info.append(country)
        
        city = geo_data.get('city')
        if city and city != 'Not found' and city is not None:
            location_info.append(city)
        
        state = geo_data.get('state')
        if state and state != 'Not found' and state is not None:
            location_info.append(state)
        
        if location_info:
            location_str = ', '.join(location_info)
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} GeoLocation: {Fore.GREEN}{location_str}")
            
            # Remove verbose debug logging for cleaner output
        else:
            logger.warning(f"No useful location information found for IP {ip}")
            
    except UnicodeError as e:
        logger.error(f"Unicode error processing domain {domain}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Unexpected error during geolocation scan of {domain}: {str(e)}")

def get_detailed_location_info(domain: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed location information for a domain.
    
    Args:
        domain: Domain or URL to look up
        
    Returns:
        Dictionary with detailed location information or None if lookup fails
    """
    try:
        clean_domain = extract_domain_from_url(domain.strip())
        
        if not clean_domain:
            return None
        
        ip = socket.gethostbyname(clean_domain)
        geo_data = get_geolocation_data(ip)
        
        if geo_data:
            return {
                'domain': clean_domain,
                'ip': ip,
                'country': geo_data.get('country_name'),
                'city': geo_data.get('city'),
                'state': geo_data.get('state'),
                'latitude': geo_data.get('latitude'),
                'longitude': geo_data.get('longitude'),
                'timezone': geo_data.get('timezone'),
                'isp': geo_data.get('ISP')
            }
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting detailed location info for {domain}: {str(e)}")
        return None