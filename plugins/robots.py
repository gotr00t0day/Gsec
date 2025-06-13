from colorama import Fore
from urllib.parse import urljoin
from plugins import agent_list
import requests
import logging
import os
from typing import Optional
from modules import format_info

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def robots_scan(domain: str) -> Optional[str]:
    """
    Scan for robots.txt file and save its content.
    
    Args:
        domain: Domain or URL to scan
        
    Returns:
        Path to saved file or None if not found
    """
    if not domain or not domain.strip():
        logger.error("Domain cannot be empty")
        return None
    
    try:
        # Construct proper robots.txt URL
        robots_url = urljoin(domain if domain.startswith(('http://', 'https://')) else f'http://{domain}', '/robots.txt')
        
        # Make request with timeout
        response = requests.get(robots_url, verify=False, headers=header, timeout=10)
        
        if response.status_code == 200:
            content = response.text
            
            if content and content.strip():
                # Ensure output directory exists
                output_dir = "output"
                if not os.path.exists(output_dir):
                    try:
                        os.makedirs(output_dir)
                    except OSError as e:
                        logger.error(f"Failed to create output directory: {str(e)}")
                        return None
                
                # Save robots.txt content
                output_path = os.path.join(output_dir, "robots.txt")
                
                try:
                    with open(output_path, "w", encoding='utf-8') as f:
                        f.write(content)
                    
                    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Robots: {Fore.MAGENTA}Content saved to /{output_path}")
                    
                    # Log some basic stats
                    lines = content.split('\n')
                    disallow_count = len([line for line in lines if line.strip().startswith('Disallow:')])
                    allow_count = len([line for line in lines if line.strip().startswith('Allow:')])
                    
                    if disallow_count > 0 or allow_count > 0:
                        print(f"{Fore.YELLOW}    Found {disallow_count} Disallow and {allow_count} Allow directives")
                    
                    return output_path
                    
                except IOError as e:
                    logger.error(f"Failed to save robots.txt: {str(e)}")
                    return None
            else:
                logger.warning(f"Empty robots.txt found at {robots_url}")
                return None
        else:
            return None
            
    except requests.exceptions.Timeout:
        logger.error(f"Timeout while fetching robots.txt from {domain}")
        return None
        
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error while fetching robots.txt from {domain}")
        return None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while fetching robots.txt from {domain}: {str(e)}")
        return None
        
    except Exception as e:
        logger.error(f"Unexpected error scanning robots.txt for {domain}: {str(e)}")
        return None

def parse_robots_content(content: str) -> dict:
    """
    Parse robots.txt content and extract meaningful information.
    
    Args:
        content: robots.txt file content
        
    Returns:
        Dictionary with parsed robots.txt information
    """
    if not content:
        return {}
    
    lines = content.split('\n')
    parsed_data = {
        'user_agents': [],
        'disallow': [],
        'allow': [],
        'sitemaps': [],
        'crawl_delay': None,
        'other_directives': []
    }
    
    current_user_agent = None
    
    for line in lines:
        line = line.strip()
        
        if not line or line.startswith('#'):
            continue
        
        if ':' in line:
            directive, value = line.split(':', 1)
            directive = directive.strip().lower()
            value = value.strip()
            
            if directive == 'user-agent':
                current_user_agent = value
                parsed_data['user_agents'].append(value)
            elif directive == 'disallow':
                parsed_data['disallow'].append({'user_agent': current_user_agent, 'path': value})
            elif directive == 'allow':
                parsed_data['allow'].append({'user_agent': current_user_agent, 'path': value})
            elif directive == 'sitemap':
                parsed_data['sitemaps'].append(value)
            elif directive == 'crawl-delay':
                try:
                    parsed_data['crawl_delay'] = float(value)
                except ValueError:
                    pass
            else:
                parsed_data['other_directives'].append({'directive': directive, 'value': value})
    
    return parsed_data

def get_interesting_paths(domain: str) -> Optional[list]:
    """
    Get interesting paths from robots.txt that might be worth investigating.
    
    Args:
        domain: Domain to check
        
    Returns:
        List of interesting paths or None if no robots.txt found
    """
    robots_url = urljoin(domain if domain.startswith(('http://', 'https://')) else f'http://{domain}', '/robots.txt')
    
    try:
        response = requests.get(robots_url, verify=False, headers=header, timeout=10)
        
        if response.status_code == 200:
            parsed = parse_robots_content(response.text)
            
            interesting_paths = []
            
            # Look for potentially interesting disallowed paths
            for entry in parsed['disallow']:
                path = entry['path']
                if path and path != '/':
                    # Filter out obviously uninteresting paths
                    if not any(skip in path.lower() for skip in ['css', 'js', 'img', 'static', 'assets']):
                        interesting_paths.append(path)
            
            return list(set(interesting_paths))  # Remove duplicates
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting interesting paths from {domain}: {str(e)}")
        return None