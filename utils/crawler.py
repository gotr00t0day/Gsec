import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import os

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}

def scan(url: str) -> None:
    try:
        with requests.Session() as session:
            session.headers.update(HEADERS)
            response = session.get(url, verify=False)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            links = {urljoin(url, a['href']) for a in soup.find_all('a', href=True)}

            os.makedirs('output', exist_ok=True)
            with open("output/spider.txt", "w") as f:
                for link in sorted(links):
                    f.write(f"{link}\n")

        print(f"Crawler: Found {len(links)} unique links.")
    except requests.RequestException as e:
        print(f"Error crawling {url}: {e}")
    except IOError as e:
        print(f"Error writing to file: {e}")
        