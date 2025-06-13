from builtwith import builtwith
from colorama import Fore
import logging

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def Tech(url: str) -> str:
    """
    Analyze website technologies using builtwith library with proper error handling.
    
    Args:
        url: Target URL to analyze
    """
    tech = []
    desc = []
    total = []
    
    try:
        info = builtwith(f"{url}")
        
        if not info:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Technologies: {Fore.YELLOW}No technologies detected")
            return
        
        for key, value in info.items():
           tech.append(key)
           desc.append(value)
        
        for tech_name, descriptions in zip(tech, desc):
            for description in descriptions:
                total.append(f"{tech_name}:{Fore.CYAN}{description}")
        
        if total:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Technologies: {Fore.GREEN}{', '.join(map(str,total))}")
        else:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Technologies: {Fore.YELLOW}No specific technologies identified")
            
    except UnicodeDecodeError as e:
        # Handle compressed content or encoding issues - no warning log to keep output clean
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Technologies: {Fore.YELLOW}Content encoding issue - unable to analyze")
        
    except AttributeError as e:
        # Handle missing attributes in response - no warning log to keep output clean
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Technologies: {Fore.YELLOW}Unable to analyze - response format issue")
        
    except Exception as e:
        # Handle any other unexpected errors - only log truly unexpected errors
        logger.error(f"Unexpected error analyzing {url}: {str(e)}")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Technologies: {Fore.RED}Analysis failed - {str(e)}")

def safe_builtwith(url: str) -> dict:
    """
    Safe wrapper for builtwith function with comprehensive error handling.
    
    Args:
        url: Target URL to analyze
        
    Returns:
        Dictionary of technologies or empty dict if analysis fails
    """
    try:
        result = builtwith(url)
        return result if result else {}
    except UnicodeDecodeError:
        # Silent handling for compressed content - no warning log needed
        return {}
    except Exception as e:
        # Only log truly unexpected errors
        logger.error(f"Error in builtwith analysis for {url}: {str(e)}")
        return {}