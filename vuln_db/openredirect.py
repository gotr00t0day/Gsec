import requests, re, sys
from colorama import Fore
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor


def is_valid(url):
    """
    Check if a given url is valid.
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_all_links(url):
    """
    Get all links present on a web page.
    """
    try:
        response = requests.get(url)
    except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
        return []
    return re.findall('href="(.*?)"', response.content.decode(errors="ignore"))

def get_redirect(url):
    """
    Check if a given url redirects to another url.
    """
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code in [301, 302]:
            return response.headers.get('Location')
    except:
        pass
    return None

def scan_website(base_url, links):
    """
    Scan a given website for open redirect vulnerabilities.
    """
    vulnerable_links = []
    link_url = urljoin(base_url, links)
    if is_valid(link_url):
        redirect_url = get_redirect(link_url)
        if redirect_url and base_url not in redirect_url:
            vulnerable_links.append(link_url)
    return vulnerable_links

if __name__ == "__main__":
    base_url = sys.argv[1]
    links = get_all_links(base_url)

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(scan_website, [base_url]*len(links), links)

    vulnerable_links = []
    for result in results:
        vulnerable_links.extend(result)

    for link in vulnerable_links:
        print(f"{Fore.GREEN}{link}")