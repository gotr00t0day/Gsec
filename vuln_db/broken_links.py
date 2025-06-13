from urllib.parse import urljoin, urlparse
from colorama import Fore
import requests
import re
import urllib3
import concurrent.futures
import os
import logging
from typing import Set, Optional, List

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings()

class BrokenLinksScanner:
    """Advanced broken links scanner with improved performance and connection management."""
    
    def __init__(self):
        # Create session with proper connection pooling
        self.session = requests.Session()
        
        # Configure connection pool to prevent warnings
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,  # Increased pool size
            pool_maxsize=20,      # Increased max size
            max_retries=1,        # Add retry logic
            pool_block=False      # Don't block when pool is full
        )
        
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Social media platforms to specifically check
        self.social_platforms = [
            "instagram", "facebook", "github", "twitter", "linkedin", 
            "youtube", "tiktok", "snapchat", "pinterest", "reddit"
        ]
    
    def validate_url(self, url: str) -> bool:
        """
        Validate if URL has proper format.
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and bool(parsed.scheme) and parsed.scheme in ['http', 'https']
        except Exception:
            return False
    
    def check_link_status(self, link: str) -> Optional[str]:
        """
        Check if a link is broken (returns 404 or connection error).
        
        Args:
            link: URL to check
            
        Returns:
            URL if broken, None if working
        """
        try:
            # Skip invalid URLs
            if not self.validate_url(link):
                return None
            
            response = self.session.get(
                link, 
                verify=False, 
                timeout=10,
                allow_redirects=True
            )
            
            # Consider various error status codes as broken
            if response.status_code in [404, 403, 500, 502, 503, 504]:
                return link
                
        except (requests.exceptions.RequestException, 
                urllib3.exceptions.ReadTimeoutError,
                requests.exceptions.ReadTimeout,
                requests.exceptions.InvalidURL,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as e:
            # Connection errors also indicate broken links
            logger.error(f"Error checking {link}: {str(e)}")
            return link
        except Exception as e:
            logger.error(f"Unexpected error checking {link}: {str(e)}")
            return None
        
        return None
    
    def extract_links(self, url: str) -> Set[str]:
        """
        Extract all links from a webpage.
        
        Args:
            url: Target URL to extract links from
            
        Returns:
            Set of unique absolute URLs
        """
        links = set()
        
        try:
            response = self.session.get(url, verify=False, timeout=15)
            response.raise_for_status()
            
            # Extract href links
            href_links = re.findall(r'href\s*=\s*["\']([^"\']*)["\']', response.text, re.IGNORECASE)
            
            # Extract src links (images, scripts, etc.)
            src_links = re.findall(r'src\s*=\s*["\']([^"\']*)["\']', response.text, re.IGNORECASE)
            
            # Combine all links
            all_links = href_links + src_links
            
            # Convert to absolute URLs and filter valid ones
            for link in all_links:
                if link:  # Skip empty links
                    absolute_url = urljoin(url, link)
                    if self.validate_url(absolute_url):
                        links.add(absolute_url)
                        
        except Exception as e:
            logger.error(f"Error extracting links from {url}: {str(e)}")
        
        return links
    
    def categorize_broken_links(self, broken_links: Set[str]) -> tuple[Set[str], Set[str]]:
        """
        Categorize broken links into social media and other links.
        
        Args:
            broken_links: Set of broken URLs
            
        Returns:
            Tuple of (social_links, other_links)
        """
        social_links = set()
        other_links = set()
        
        for link in broken_links:
            is_social = False
            for platform in self.social_platforms:
                if platform.lower() in link.lower():
                    social_links.add(link)
                    is_social = True
                    break
            
            if not is_social:
                other_links.add(link)
        
        return social_links, other_links
    
    def save_results(self, broken_links: Set[str], social_links: Set[str]) -> None:
        """
        Save broken links results to file.
        
        Args:
            broken_links: Set of all broken links
            social_links: Set of broken social media links
        """
        try:
            # Ensure output directory exists
            output_dir = os.path.join(os.getcwd(), "output")
            os.makedirs(output_dir, exist_ok=True)
            
            # Save all broken links
            if broken_links:
                broken_file = os.path.join(output_dir, "broken_links.txt")
                with open(broken_file, "w", encoding='utf-8') as f:
                    f.write("=== Broken Links Report ===\n\n")
                    f.write(f"Total broken links found: {len(broken_links)}\n\n")
                    
                    # Separate social and other links in the file
                    if social_links:
                        f.write("--- Broken Social Media Links ---\n")
                        for link in sorted(social_links):
                            f.write(f"{link}\n")
                        f.write("\n")
                    
                    other_links = broken_links - social_links
                    if other_links:
                        f.write("--- Other Broken Links ---\n")
                        for link in sorted(other_links):
                            f.write(f"{link}\n")
                            
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")

def scan(url: str) -> None:
    """
    Main broken links scanning function with improved error handling and performance.
    
    Args:
        url: Target URL to scan for broken links
    """
    if not url or not url.strip():
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: URL cannot be empty")
        return
    
    scanner = BrokenLinksScanner()
    
    try:
        # Validate target URL
        if not scanner.validate_url(url):
            print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error: Invalid URL format")
            return
        
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Starting broken links scan for: {Fore.GREEN}{url}")
        
        # Extract all links from the page
        links = scanner.extract_links(url)
        
        if not links:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No links found on the target page")
            return
        
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Found {len(links)} link(s) to check")
        
        # Check links for broken status using thread pool
        broken_links = set()
        
        # Use limited number of workers to prevent connection pool issues
        max_workers = min(10, len(links))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all link checks
            future_to_link = {executor.submit(scanner.check_link_status, link): link for link in links}
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_link, timeout=60):
                try:
                    result = future.result(timeout=5)
                    if result:
                        broken_links.add(result)
                except concurrent.futures.TimeoutError:
                    # Skip timeouts
                    continue
                except Exception as e:
                    logger.error(f"Error processing link check: {str(e)}")
                    continue
        
        # Categorize broken links
        social_links, other_links = scanner.categorize_broken_links(broken_links)
        
        # Report results
        if broken_links:
            if social_links:
                social_list = list(social_links)[:5]  # Show first 5
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Broken Social Links: {Fore.GREEN}{', '.join(social_list)}")
                if len(social_links) > 5:
                    print(f"{Fore.CYAN}[*] {Fore.CYAN}-{Fore.WHITE} ... and {len(social_links) - 5} more social links")
            
            if other_links:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Other Broken Links: {Fore.RED}{len(other_links)} found")
            
            # Save results
            scanner.save_results(broken_links, social_links)
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Broken Links Report: {Fore.GREEN}Saved to /output/broken_links.txt")
        else:
            print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No broken links found")
        
    except Exception as e:
        logger.error(f"Broken links scan error: {str(e)}")
        print(f"{Fore.RED}[-] {Fore.CYAN}-{Fore.WHITE} Error during broken links scan: {str(e)}")
    finally:
        # Clean up session
        scanner.session.close()

# Legacy function for backward compatibility
def validate(url: str) -> bool:
    """Legacy function for backward compatibility."""
    scanner = BrokenLinksScanner()
    return scanner.validate_url(url)

def check_link(link: str, session: requests.Session) -> Optional[str]:
    """Legacy function for backward compatibility."""
    scanner = BrokenLinksScanner()
    scanner.session = session
    return scanner.check_link_status(link)