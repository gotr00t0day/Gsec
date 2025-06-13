import random
import logging
from typing import Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Modern user agents - updated and more realistic
_useragent_list = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    
    # Chrome (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    
    # Firefox (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
    
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    
    # Safari (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    
    # Mobile Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    
    # Mobile Safari (iOS)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    
    # Legacy Chrome for compatibility
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36",
    
    # More diverse options for evasion
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
]

# Cache for random selections to avoid repeated expensive operations
_cached_agent: Optional[str] = None
_selection_counter = 0
_cache_refresh_interval = 100

def get_useragent() -> str:
    """
    Get a random user agent string with caching for performance.
    
    Returns:
        A random user agent string
    """
    global _cached_agent, _selection_counter
    
    # Refresh cache periodically or if not set
    if _cached_agent is None or _selection_counter >= _cache_refresh_interval:
        _cached_agent = random.choice(_useragent_list)
        _selection_counter = 0
        logger.debug(f"Selected new user agent: {_cached_agent}")
    
    _selection_counter += 1
    return _cached_agent

def get_random_useragent() -> str:
    """
    Get a truly random user agent string (no caching).
    
    Returns:
        A random user agent string
    """
    return random.choice(_useragent_list)

def get_desktop_useragent() -> str:
    """
    Get a random desktop user agent string.
    
    Returns:
        A random desktop user agent string
    """
    desktop_agents = [ua for ua in _useragent_list if 'Mobile' not in ua and 'iPhone' not in ua and 'iPad' not in ua and 'Android' not in ua]
    return random.choice(desktop_agents) if desktop_agents else get_useragent()

def get_mobile_useragent() -> str:
    """
    Get a random mobile user agent string.
    
    Returns:
        A random mobile user agent string
    """
    mobile_agents = [ua for ua in _useragent_list if any(mobile in ua for mobile in ['Mobile', 'iPhone', 'iPad', 'Android'])]
    return random.choice(mobile_agents) if mobile_agents else get_useragent()

def get_chrome_useragent() -> str:
    """
    Get a random Chrome user agent string.
    
    Returns:
        A random Chrome user agent string
    """
    chrome_agents = [ua for ua in _useragent_list if 'Chrome' in ua and 'Edg' not in ua]
    return random.choice(chrome_agents) if chrome_agents else get_useragent()

def get_firefox_useragent() -> str:
    """
    Get a random Firefox user agent string.
    
    Returns:
        A random Firefox user agent string
    """
    firefox_agents = [ua for ua in _useragent_list if 'Firefox' in ua]
    return random.choice(firefox_agents) if firefox_agents else get_useragent()

def get_useragent_stats() -> dict:
    """
    Get statistics about available user agents.
    
    Returns:
        Dictionary with user agent statistics
    """
    total = len(_useragent_list)
    chrome_count = len([ua for ua in _useragent_list if 'Chrome' in ua and 'Edg' not in ua])
    firefox_count = len([ua for ua in _useragent_list if 'Firefox' in ua])
    safari_count = len([ua for ua in _useragent_list if 'Safari' in ua and 'Chrome' not in ua])
    edge_count = len([ua for ua in _useragent_list if 'Edg' in ua])
    mobile_count = len([ua for ua in _useragent_list if any(mobile in ua for mobile in ['Mobile', 'iPhone', 'iPad', 'Android'])])
    
    return {
        'total': total,
        'chrome': chrome_count,
        'firefox': firefox_count,
        'safari': safari_count,
        'edge': edge_count,
        'mobile': mobile_count,
        'desktop': total - mobile_count
    }